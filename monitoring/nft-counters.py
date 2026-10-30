#!/usr/bin/env python3
"""Export nftables drop-rule counters as Prometheus text (textfile collector format).

Reads `nft -j list ruleset` (needs root) or a saved JSON dump, and writes one
sample per counted drop rule:

    home_dns_nft_drop_packets_total{family,table,chain,rule}
    home_dns_nft_drop_bytes_total{family,table,chain,rule}

`rule` is the rule's comment when it has one ("drop India IPv4 DNS in"),
otherwise a name built from its matches, e.g. "ip_saddr_not_listed4_th_dport_53_853".
Rule handles are not used: they change every time a table is reloaded.

    sudo monitoring/nft-counters.py --output /var/lib/home-dns/metrics/nft.prom
    monitoring/nft-counters.py --input dump.json          # no root, prints to stdout

Writes are atomic (temp file + rename), so a reader never sees half a file.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

PREFIX = "home_dns_nft"


def _slug(s):
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", str(s).lower())).strip("_")


def _operand(v):
    """Short name for one side of a match expression."""
    if isinstance(v, dict):
        if "payload" in v:
            p = v["payload"]
            return f"{p.get('protocol', 'raw')}_{p.get('field', 'data')}"
        if "meta" in v:
            return f"meta_{v['meta'].get('key', '')}"
        if "socket" in v:
            return f"socket_{v['socket'].get('key', '')}"
        if "ct" in v:
            return f"ct_{v['ct'].get('key', '')}"
        if "set" in v:
            return "_".join(_operand(x) for x in v["set"])
        if "prefix" in v:
            return f"{v['prefix'].get('addr')}_{v['prefix'].get('len')}"
        if "range" in v:
            return "_".join(str(x) for x in v["range"])
        return next(iter(v), "x")
    if isinstance(v, list):
        return "_".join(_operand(x) for x in v)
    if isinstance(v, str) and v.startswith("@"):
        return v[1:]
    return str(v)


def rule_name(rule):
    if rule.get("comment"):
        return rule["comment"]
    parts = []
    for e in rule.get("expr", []):
        m = e.get("match")
        if not m:
            continue
        left, right = _operand(m.get("left")), _operand(m.get("right"))
        op = m.get("op", "==")
        if op in ("==", "in"):
            parts.append(f"{left}_{right}")
        elif op == "!=":
            parts.append(f"{left}_not_{right}")
        else:
            parts.append(f"{left}_{_slug(op)}_{right}")
    return _slug("_".join(parts)) or "unnamed"


def drop_counters(ruleset, table_re=".*", all_rules=False):
    """[(labels, packets, bytes)] for every counted drop rule in matching tables."""
    tre = re.compile(table_re)
    out, seen = [], {}
    for item in ruleset.get("nftables", []):
        rule = item.get("rule")
        if not rule or not tre.fullmatch(rule.get("table", "")):
            continue
        expr = rule.get("expr", [])
        counter = next((e["counter"] for e in expr if "counter" in e), None)
        if counter is None or not isinstance(counter, dict):
            continue
        if not all_rules and not any("drop" in e for e in expr):
            continue
        labels = {"family": rule["family"], "table": rule["table"], "chain": rule["chain"],
                  "rule": rule_name(rule)}
        key = tuple(labels.values())
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            labels["rule"] += f" #{seen[key]}"
        out.append((labels, int(counter.get("packets", 0)), int(counter.get("bytes", 0))))
    return out


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(samples, up=1, now=None):
    now = time.time() if now is None else now
    lines = [
        f"# HELP {PREFIX}_counters_up 1 if nft -j list ruleset succeeded on the last run",
        f"# TYPE {PREFIX}_counters_up gauge",
        f"{PREFIX}_counters_up {up}",
        f"# HELP {PREFIX}_counters_timestamp_seconds When these counters were read",
        f"# TYPE {PREFIX}_counters_timestamp_seconds gauge",
        f"{PREFIX}_counters_timestamp_seconds {int(now)}",
    ]
    for metric, idx, what in (("drop_packets_total", 1, "Packets"), ("drop_bytes_total", 2, "Bytes")):
        name = f"{PREFIX}_{metric}"
        lines += [f"# HELP {name} {what} dropped by an nftables rule with a counter",
                  f"# TYPE {name} counter"]
        for s in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in s[0].items())
            lines.append(f"{name}{{{lab}}} {s[idx]}")
    return "\n".join(lines) + "\n"


def write_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".nft-counters.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--input", help="saved `nft -j list ruleset` JSON instead of running nft")
    ap.add_argument("--output", help="write here atomically (default: stdout)")
    ap.add_argument("--tables", default=".*", help="regex of table names to export (default: all)")
    ap.add_argument("--all", action="store_true", help="every counted rule, not only drop rules")
    ap.add_argument("--nft", default="nft")
    a = ap.parse_args(argv)
    up, samples = 1, []
    try:
        if a.input:
            with open(a.input) as f:
                data = json.load(f)
        else:
            data = json.loads(subprocess.run([a.nft, "-j", "list", "ruleset"], check=True,
                                             capture_output=True, text=True).stdout)
        samples = drop_counters(data, a.tables, a.all)
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f"nft-counters: {e}", file=sys.stderr)
        up = 0
    text = render(samples, up)
    if a.output:
        write_atomic(a.output, text)
    else:
        sys.stdout.write(text)
    return 0 if up else 1


if __name__ == "__main__":
    sys.exit(main())
