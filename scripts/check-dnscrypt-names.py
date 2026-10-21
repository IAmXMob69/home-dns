#!/usr/bin/env python3
"""Check dnscrypt-proxy.toml server and relay names against the live lists.

Fails when a server or relay name no longer exists, when a relay name is
double-prefixed, when a route uses a wildcard dnscrypt-proxy does not support,
when a routed server is not DNSCrypt (relays only carry DNSCrypt), or when a
server is routed via a relay run by the same operator.

Usage: check-dnscrypt-names.py [CONFIG] [--lists-dir DIR]
"""
import argparse
import base64
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/"
PROTO = {0x00: "plain", 0x01: "dnscrypt", 0x02: "doh", 0x03: "dot", 0x04: "doq",
         0x05: "odoh", 0x81: "relay", 0x85: "odoh-relay"}


def load_list(name, lists_dir):
    if lists_dir:
        return (Path(lists_dir) / f"{name}.md").read_text()
    with urllib.request.urlopen(BASE + f"{name}.md", timeout=30) as r:
        return r.read().decode()


def parse_md(text):
    out, name, desc, stamps = {}, None, [], []
    for line in text.splitlines():
        if line.startswith("## "):
            if name:
                out[name] = (" ".join(desc), stamps)
            name, desc, stamps = line[3:].strip(), [], []
        elif line.startswith("sdns://"):
            stamps.append(line.strip())
        elif name and line.strip():
            desc.append(line.strip())
    if name:
        out[name] = (" ".join(desc), stamps)
    return out


def decode(stamp):
    b = stamp[7:]
    raw = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
    proto = raw[0]
    if proto in (0x81, 0x85):
        n = raw[1]
        addr = raw[2:2 + n].decode()
    else:
        n = raw[9]
        addr = raw[10:10 + n].decode()
    host = addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr
    return PROTO.get(proto, hex(proto)), host


def operator(desc):
    m = re.search(r"(?:operated|maintained) by ([^.,(]+)", desc, re.IGNORECASE)
    return m.group(1).strip().lower() if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config", nargs="?", default="dnscrypt/dnscrypt-proxy.toml")
    ap.add_argument("--lists-dir", help="read <name>.md from here instead of the network")
    a = ap.parse_args()
    cfg = tomllib.loads(Path(a.config).read_text())
    errors = []

    servers, relays = {}, {}
    for src_name, src in cfg.get("sources", {}).items():
        url = (src.get("urls") or [""])[0]
        list_name = url.rsplit("/", 1)[-1].removesuffix(".md")
        entries = parse_md(load_list(list_name, a.lists_dir))
        prefix = src.get("prefix", "")
        for name, val in entries.items():
            if prefix and name.startswith(prefix):
                errors.append(f"source [{src_name}]: prefix '{prefix}' doubles up on '{name}'")
                break
        for name, val in entries.items():
            kind, _ = decode(val[1][0]) if val[1] else ("?", "")
            (relays if kind in ("relay", "odoh-relay") else servers)[prefix + name] = val

    names = cfg.get("server_names") or []
    for n in names:
        if n not in servers:
            errors.append(f"server_names: '{n}' is not in the live lists")

    anon = cfg.get("anonymized_dns", {})
    for route in anon.get("routes", []):
        sname, via = route.get("server_name", ""), route.get("via", [])
        if "*" in sname and sname != "*":
            errors.append(f"route '{sname}': only '*' is a wildcard; this matches nothing")
            continue
        targets = names if sname == "*" else [sname]
        for r in via:
            if r != "*" and r not in relays:
                errors.append(f"route '{sname}': relay '{r}' is not in the live lists")
        for t in targets:
            if t not in servers:
                if sname != "*":
                    errors.append(f"route '{sname}': server is not in the live lists")
                continue
            if sname != "*" and t not in names:
                errors.append(f"route '{sname}': server is not in server_names")
            desc, stamps = servers[t]
            kind, host = decode(stamps[0])
            if kind != "dnscrypt":
                errors.append(f"route '{t}': {kind} cannot use Anonymized DNS relays")
                continue
            for r in via:
                if r == "*" or r not in relays:
                    continue
                rdesc, rstamps = relays[r]
                _, rhost = decode(rstamps[0])
                same_op = operator(desc) and operator(desc) == operator(rdesc)
                if rhost == host or same_op:
                    errors.append(f"route '{t}': relay '{r}' is run by the same operator")

    if names and anon.get("routes"):
        routed = {r.get("server_name") for r in anon["routes"]}
        for n in names:
            if "*" not in routed and n not in routed:
                errors.append(f"server '{n}' has no relay route")

    for e in errors:
        print(f"E: {e}")
    print(f"{len(names)} servers, {len(anon.get('routes', []))} routes, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
