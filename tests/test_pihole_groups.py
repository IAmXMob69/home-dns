#!/usr/bin/env python3
"""Run scripts/geolock-pihole.sh against a mocked Pi-hole v6 API.

Checks: allowlist entries are never flipped, hand-added deny entries are left
alone, stale script-owned entries are pruned, the group switch is preserved,
and a second run is a no-op.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "geolock/pihole/domains-india.txt"
first_two = [ln.strip().lower() for ln in LIST.read_text().splitlines()
             if ln.strip() and not ln.startswith("#")][:2]
ALLOWED, HAND_DENY = first_two
first_two_regex = next(ln.strip() for ln in (ROOT / "geolock/pihole/regex.txt").read_text().splitlines()
                       if ln.strip() and not ln.startswith("#"))

DB = {
    "groups": [{"id": 0, "name": "Default", "comment": "", "enabled": True},
               {"id": 1, "name": "Geo-Location Lock", "comment": "old", "enabled": False}],
    "domains": [
        {"id": 1, "domain": ALLOWED, "type": "allow", "kind": "exact", "comment": "my allowlist",
         "groups": [0], "enabled": True},
        {"id": 2, "domain": HAND_DENY, "type": "deny", "kind": "exact", "comment": "mine",
         "groups": [0], "enabled": True},
        {"id": 3, "domain": "removed.example.in", "type": "deny", "kind": "exact",
         "comment": "Geo lock India domain", "groups": [1], "enabled": True},
        {"id": 4, "domain": first_two_regex, "type": "deny", "kind": "regex",
         "comment": "Geo lock Indian ccTLD", "groups": [0, 1], "enabled": True},
    ],
    "clients": [{"id": 1, "client": "192.168.0.0/16", "comment": "LAN", "groups": [0]}],
}
LOG = []


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"null")

    def reply(self, code, obj=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authed(self):
        return self.headers.get("X-FTL-SID") == "sid"

    def do_POST(self):
        path, b = urlparse(self.path).path, self.body()
        if path == "/api/auth":
            ok = b.get("password") == "pw"
            return self.reply(200 if ok else 401, {"session": {"sid": "sid" if ok else None}})
        if not self.authed():
            return self.reply(401, {})
        LOG.append(("POST", path))
        if path == "/api/groups":
            g = {"id": max(x["id"] for x in DB["groups"]) + 1, **b}
            DB["groups"].append(g)
            return self.reply(201, {"groups": [g]})
        if path.startswith("/api/domains/deny/"):
            kind = path.rsplit("/", 1)[1]
            doms = b["domain"] if isinstance(b["domain"], list) else [b["domain"]]
            ok, errs = [], []
            for d in doms:
                if any(x["domain"] == d and x["type"] == "deny" and x["kind"] == kind for x in DB["domains"]):
                    errs.append({"item": d, "error": "UNIQUE constraint failed"})
                    continue
                DB["domains"].append({"id": len(DB["domains"]) + 100, "domain": d, "type": "deny", "kind": kind,
                                      "comment": b.get("comment"), "groups": b.get("groups", [0]),
                                      "enabled": b.get("enabled", True)})
                ok.append({"item": d})
            return self.reply(201, {"processed": {"success": ok, "errors": errs}})
        if path == "/api/domains:batchDelete":
            for it in b:
                DB["domains"] = [x for x in DB["domains"] if not (
                    x["domain"] == it["item"] and x["type"] == it["type"] and x["kind"] == it["kind"])]
            return self.reply(204)
        if path == "/api/clients":
            DB["clients"].append({"id": len(DB["clients"]) + 1, "client": b["client"],
                                  "comment": b.get("comment"), "groups": b.get("groups", [0])})
            return self.reply(201, {"processed": {"success": [], "errors": []}})
        return self.reply(404, {})

    def do_PUT(self):
        if not self.authed():
            return self.reply(401, {})
        path, b = urlparse(self.path).path, self.body()
        LOG.append(("PUT", path))
        parts = path.split("/")
        if path.startswith("/api/groups/"):
            g = next(x for x in DB["groups"] if x["name"] == unquote(parts[3]))
            g.update(b)
            return self.reply(200, {"groups": [g]})
        if path.startswith("/api/domains/"):
            typ, kind, dom = parts[3], parts[4], unquote(parts[5])
            x = next(x for x in DB["domains"] if (x["type"], x["kind"], x["domain"]) == (typ, kind, dom))
            x.update(b)
            return self.reply(200, {"domains": [x], "processed": {"success": [], "errors": []}})
        if path.startswith("/api/clients/"):
            c = next(x for x in DB["clients"] if x["client"] == unquote(parts[3]))
            c.update(b)
            return self.reply(200, {"clients": [c]})
        return self.reply(404, {})

    def do_GET(self):
        if not self.authed():
            return self.reply(401, {})
        path = urlparse(self.path).path
        if path.startswith("/api/groups/"):
            name = unquote(path.split("/")[3])
            return self.reply(200, {"groups": [g for g in DB["groups"] if g["name"] == name]})
        if path == "/api/domains":
            return self.reply(200, {"domains": DB["domains"]})
        if path == "/api/clients":
            return self.reply(200, {"clients": DB["clients"]})
        return self.reply(404, {})

    def do_DELETE(self):
        return self.reply(204)


def run():
    srv = HTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = {**os.environ, "PIHOLE_API": f"http://127.0.0.1:{srv.server_address[1]}", "PIHOLE_PASSWORD": "pw"}
    out = subprocess.run(["bash", str(ROOT / "scripts/geolock-pihole.sh")], env=env,
                         capture_output=True, text=True, check=False)
    srv.shutdown()
    return out


def main():
    problems = []
    out = run()
    print(out.stdout.splitlines()[0] if out.stdout else out.stderr)
    if out.returncode:
        problems.append(f"run 1 failed: {out.stderr}")
    allow = [x for x in DB["domains"] if x["domain"] == ALLOWED and x["type"] == "allow"]
    if not allow or allow[0]["groups"] != [0] or allow[0]["comment"] != "my allowlist":
        problems.append("allowlist entry was changed")
    hand = next(x for x in DB["domains"] if x["domain"] == HAND_DENY and x["type"] == "deny")
    if hand["comment"] != "mine" or hand["groups"] != [0]:
        problems.append("hand-added deny entry was changed")
    if any(x["domain"] == "removed.example.in" for x in DB["domains"]):
        problems.append("stale geo-lock entry was not pruned")
    geo = next(g for g in DB["groups"] if g["name"] == "Geo-Location Lock")
    if geo["enabled"] is not False:
        problems.append("group switch was flipped back on")
    owned = [x for x in DB["domains"] if (x["comment"] or "").startswith("Geo lock ")]
    if not owned or any(x["groups"] != [geo["id"]] for x in owned):
        problems.append("owned entries not in the Geo-Location Lock group")
    rx = next(x for x in DB["domains"] if x["domain"] == first_two_regex and x["type"] == "deny")
    if rx["comment"] != "Geo lock Indian ccTLD" or rx["groups"] != [geo["id"]]:
        problems.append("owned entry: comment not kept or still in Default group")
    lan = next(c for c in DB["clients"] if c["client"] == "192.168.0.0/16")
    if set(lan["groups"]) != {0, geo["id"]} or lan["comment"] != "LAN":
        problems.append("existing client not merged into group correctly")

    LOG.clear()
    out = run()
    print(out.stdout.splitlines()[0] if out.stdout else out.stderr)
    writes = [x for x in LOG if x[0] in ("POST", "PUT")]
    if out.returncode or writes:
        problems.append(f"second run was not a no-op: {writes[:5]}")

    for p in problems:
        print(f"FAIL: {p}")
    print("group sync test:", "FAIL" if problems else "OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
