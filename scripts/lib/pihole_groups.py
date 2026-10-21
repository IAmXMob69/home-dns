#!/usr/bin/env python3
"""Sync a toggleable Pi-hole group through the Pi-hole v6 API.

Never writes gravity.db directly. Rules:
- Only deny entries are created. Allow entries are never touched.
- An entry is "ours" when its comment starts with --tag. Only ours get
  updated, and ours that are no longer in the source lists get deleted.
- A deny entry the user added by hand (other comment) is left alone.
- The group's on/off switch is kept as the user left it.

Password: PIHOLE_PASSWORD, else FTLCONF_webserver_api_password from .env.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = [
    ("0.0.0.0/0", "All IPv4 devices, so the group switch applies house-wide"),
    ("::/0", "All IPv6 devices"),
    ("127.0.0.1", "This computer"),
    ("::1", "This computer IPv6"),
    ("192.168.0.0/16", "Typical home LAN"),
    ("10.0.0.0/8", "Private LAN"),
    ("172.16.0.0/12", "Private LAN / Docker"),
]


class ApiError(RuntimeError):
    pass


def read_env_password(path):
    if not path.is_file():
        return ""
    for line in path.read_text().splitlines():
        key, sep, val = line.strip().partition("=")
        if sep and key == "FTLCONF_webserver_api_password":
            return val.strip().strip("'\"")
    return ""


class Api:
    def __init__(self, base, password):
        self.base = base.rstrip("/")
        self.sid = None
        if password:
            r = self.call("POST", "/api/auth", {"password": password}, auth=False)
            self.sid = (r.get("session") or {}).get("sid")
            if not self.sid:
                raise ApiError("Pi-hole rejected the password")

    def call(self, method, path, body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if auth and self.sid:
            req.add_header("X-FTL-SID", self.sid)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 and method == "GET":
                return None
            detail = e.read().decode(errors="replace")[:300]
            raise ApiError(f"{method} {path}: HTTP {e.code} {detail}") from e
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach Pi-hole at {self.base}: {e.reason}") from e
        return json.loads(raw) if raw else {}

    def logout(self):
        if self.sid:
            try:
                self.call("DELETE", "/api/auth")
            except ApiError:
                pass


def q(s):
    return urllib.parse.quote(s, safe="")


def ensure_group(api, name, desc, dry):
    r = api.call("GET", f"/api/groups/{q(name)}")
    groups = (r or {}).get("groups") or []
    if groups:
        g = groups[0]
        if g.get("comment") != desc and not dry:
            api.call("PUT", f"/api/groups/{q(name)}",
                     {"name": name, "comment": desc, "enabled": g.get("enabled", True)})
        return g["id"]
    if dry:
        print(f"would create group '{name}'")
        return -1
    r = api.call("POST", "/api/groups", {"name": name, "comment": desc, "enabled": True})
    for g in r.get("groups") or []:
        if g.get("name") == name:
            return g["id"]
    r = api.call("GET", f"/api/groups/{q(name)}")
    return r["groups"][0]["id"]


def check_processed(r, what):
    errs = ((r or {}).get("processed") or {}).get("errors") or []
    if errs:
        raise ApiError(f"{what}: {errs[:5]}")


def sync(api, group, desc, tag, desired, dry=False, prune=True):
    """desired: dict {(kind, domain): comment}."""
    gid = ensure_group(api, group, desc, dry)
    current = api.call("GET", "/api/domains").get("domains") or []
    deny = {(d["kind"], d["domain"]): d for d in current if d.get("type") == "deny"}
    allow = {(d["kind"], d["domain"]) for d in current if d.get("type") == "allow"}

    to_add, to_fix, skipped = {}, [], []
    for key, comment in desired.items():
        have = deny.get(key)
        if have is None:
            to_add.setdefault((key[0], comment), []).append(key[1])
        elif not (have.get("comment") or "").startswith(tag):
            skipped.append(key)
        elif have.get("comment") != comment or sorted(have.get("groups") or []) != [gid]:
            to_fix.append((key, comment, have))
    stale = [d for key, d in deny.items()
             if (d.get("comment") or "").startswith(tag) and key not in desired]

    n_add = sum(len(v) for v in to_add.values())
    print(f"{group}: add {n_add}, update {len(to_fix)}, "
          f"remove {len(stale) if prune else 0}, left alone (yours) {len(skipped)}")
    shadowed = [k for k in desired if k in allow]
    if shadowed:
        print(f"note: {len(shadowed)} of these are also on your allowlist; allow wins, untouched")
    if dry:
        return

    for (kind, comment), domains in to_add.items():
        for i in range(0, len(domains), 500):
            r = api.call("POST", f"/api/domains/deny/{kind}",
                         {"domain": domains[i:i + 500], "comment": comment,
                          "groups": [gid], "enabled": True})
            check_processed(r, f"add {kind}")
    for (kind, domain), comment, have in to_fix:
        r = api.call("PUT", f"/api/domains/deny/{kind}/{q(domain)}",
                     {"type": "deny", "kind": kind, "comment": comment,
                      "groups": [gid], "enabled": have.get("enabled", True)})
        check_processed(r, f"update {domain}")
    if prune and stale:
        for i in range(0, len(stale), 500):
            api.call("POST", "/api/domains:batchDelete",
                     [{"item": d["domain"], "type": "deny", "kind": d["kind"]} for d in stale[i:i + 500]])

    clients = {c["client"]: c for c in api.call("GET", "/api/clients").get("clients") or []}
    for ip, comment in CLIENTS:
        have = clients.get(ip)
        if have is None:
            api.call("POST", "/api/clients", {"client": ip, "comment": comment, "groups": [0, gid]})
        elif not {0, gid} <= set(have.get("groups") or []):
            groups = sorted(set(have.get("groups") or []) | {0, gid})
            api.call("PUT", f"/api/clients/{q(ip)}",
                     {"comment": have.get("comment") or comment, "groups": groups})


def load_lists(args):
    desired = {}
    for spec in args.exact or []:
        path, _, comment = spec.partition(":")
        for line in Path(path).read_text().splitlines():
            d = line.strip().lower()
            if d and not d.startswith("#"):
                desired[("exact", d)] = comment
    for spec in args.regex or []:
        path, _, comment = spec.partition(":")
        for line in Path(path).read_text().splitlines():
            d = line.strip()
            if d and not d.startswith("#"):
                desired[("regex", d)] = comment
    for path in args.tsv or []:
        for line in Path(path).read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or parts[0].strip() not in ("1", "3"):
                continue
            kind = "exact" if parts[0].strip() == "1" else "regex"
            dom = parts[1].strip().lower() if kind == "exact" else parts[1].strip()
            desired[(kind, dom)] = args.tag + parts[2].strip()
    return desired


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--group", required=True)
    ap.add_argument("--description", required=True)
    ap.add_argument("--tag", required=True, help="comment prefix that marks entries this script owns")
    ap.add_argument("--exact", action="append", metavar="FILE:COMMENT")
    ap.add_argument("--regex", action="append", metavar="FILE:COMMENT")
    ap.add_argument("--tsv", action="append", metavar="FILE", help="type<TAB>domain<TAB>comment rows")
    ap.add_argument("--api", default=os.environ.get("PIHOLE_API", "http://127.0.0.1"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-prune", action="store_true")
    args = ap.parse_args()

    desired = load_lists(args)
    for comment in set(desired.values()):
        if not comment.startswith(args.tag):
            sys.exit(f"comment '{comment}' must start with tag '{args.tag}'")
    password = os.environ.get("PIHOLE_PASSWORD") or read_env_password(ROOT / ".env")
    try:
        api = Api(args.api, password)
        try:
            sync(api, args.group, args.description, args.tag, desired,
                 dry=args.dry_run, prune=not args.no_prune)
        finally:
            api.logout()
    except ApiError as e:
        sys.exit(f"pihole-groups: {e}")


if __name__ == "__main__":
    main()
