#!/usr/bin/env python3
"""Indian CA DNS tripwire: a read-only Pi-hole query watcher.

Defensive monitor only. It reads Pi-hole's long-term query database, finds any
attempt to resolve one of the Indian certificate-authority domains this project
blocks, and appends one line per new attempt to a local log. It sends nothing
to anyone, changes nothing in the DNS stack, and opens the database read-only.
Notifications are handled separately by tailing the log; the log is this
watcher's only output.

The watch list is derived from privacy-shield/privacy-shield.tsv, the same file
the Pi-hole deny rules come from, so it cannot drift from what is blocked.

Log line, tab-separated, append-only, fields in order:
    ISO-8601 timestamp <TAB> client IP <TAB> client hostname or "-" <TAB> domain

Optional environment overrides:
    CA_TRIPWIRE_LOG        log file
                           (default ${XDG_DATA_HOME:-$HOME/.local/share}/ca-tripwire/hits.log)
    CA_TRIPWIRE_CURSOR     cursor file (default next to the log)
    CA_TRIPWIRE_TSV        privacy-shield.tsv (default the copy in this repo)
    CA_TRIPWIRE_CONTAINER  Pi-hole container name (default pihole)
    CA_TRIPWIRE_DB         database path inside the container
                           (default /etc/pihole/pihole-FTL.db)
    CA_TRIPWIRE_FTL_DB     read this host-side database path directly instead of
                           going through the container (e.g. a bare-metal Pi-hole)
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# Only the regex rules beneath this heading in the TSV are watched, so the
# telemetry rules above it are never matched.
CA_SECTION = "Certificate authority lockout"


def _env_path(name, default):
    value = os.environ.get(name)
    return Path(value).expanduser() if value else default


def _data_home():
    xdg = os.environ.get("XDG_DATA_HOME")
    return Path(xdg) if xdg else Path.home() / ".local" / "share"


LOG = _env_path("CA_TRIPWIRE_LOG", _data_home() / "ca-tripwire" / "hits.log")
CURSOR = _env_path("CA_TRIPWIRE_CURSOR", LOG.parent / "cursor")
TSV = _env_path("CA_TRIPWIRE_TSV", REPO / "privacy-shield" / "privacy-shield.tsv")
CONTAINER = os.environ.get("CA_TRIPWIRE_CONTAINER", "pihole")
DB = os.environ.get("CA_TRIPWIRE_DB", "/etc/pihole/pihole-FTL.db")
HOST_DB = os.environ.get("CA_TRIPWIRE_FTL_DB")

# Candidate in-container sqlite shells, in order. The Pi-hole container ships
# the FTL binary (which embeds sqlite3) rather than a standalone sqlite3.
_SQLITE_SHELLS = (
    ["pihole-FTL", "sqlite3"],
    ["sqlite3"],
)
_shell_cache = None


def load_ca_patterns():
    if not TSV.is_file():
        sys.exit("ca-tripwire: watch list not found: " + str(TSV))
    patterns = []
    in_section = False
    for raw in TSV.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#"):
            if CA_SECTION.lower() in raw.lower():
                in_section = True
            continue
        if not in_section or not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 2 or parts[0].strip() != "3":
            continue
        try:
            patterns.append(re.compile(parts[1].strip(), re.IGNORECASE))
        except re.error as exc:
            print("ca-tripwire: skipping invalid regex %r: %s" % (parts[1], exc),
                  file=sys.stderr)
    if not patterns:
        sys.exit("ca-tripwire: no certificate-authority rules in " + str(TSV))
    return patterns


def _run(sql):
    """Run one read-only query; return rows as lists of text fields."""
    if HOST_DB:
        uri = "file:%s?mode=ro&immutable=1" % Path(HOST_DB).expanduser()
        con = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            return [["" if v is None else str(v) for v in row]
                    for row in con.execute(sql)]
        finally:
            con.close()
    global _shell_cache
    shells = [_shell_cache] if _shell_cache else []
    shells += [s for s in _SQLITE_SHELLS if s != _shell_cache]
    last = ""
    for shell in shells:
        cmd = (["docker", "exec", CONTAINER] + shell
               + ["-readonly", "-separator", "\t", DB, sql])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            sys.exit("ca-tripwire: docker not found on PATH")
        if proc.returncode == 0:
            _shell_cache = shell
            return [line.split("\t") for line in proc.stdout.splitlines() if line]
        last = proc.stderr.strip()
    raise RuntimeError(last or "no usable sqlite shell in container " + CONTAINER)


_ROWS = ("SELECT q.id, q.timestamp, COALESCE(c.ip, ''), COALESCE(c.name, ''), "
         "d.domain FROM query_storage q "
         "JOIN domain_by_id d ON d.id = q.domain "
         "LEFT JOIN client_by_id c ON c.id = q.client "
         "WHERE q.id > %d ORDER BY q.id")
_MAXID = "SELECT COALESCE(MAX(id), 0) FROM query_storage"


def _read_cursor():
    try:
        return int(CURSOR.read_text().strip())
    except (OSError, ValueError):
        return None


def _iso(ts):
    try:
        return datetime.fromtimestamp(float(ts)).astimezone().isoformat(
            timespec="seconds")
    except (ValueError, OSError):
        return str(ts)


def main():
    patterns = load_ca_patterns()
    LOG.parent.mkdir(parents=True, exist_ok=True)

    cursor = _read_cursor()
    if cursor is None:
        # First run: start from the newest query so installing the tripwire
        # does not replay history already in the database.
        baseline = int(_run(_MAXID)[0][0])
        CURSOR.write_text(str(baseline))
        print("ca-tripwire: baseline set at query id %d" % baseline)
        return 0

    rows = _run(_ROWS % cursor)
    highest = cursor
    hits = 0
    with LOG.open("a", encoding="utf-8") as log:
        for row in rows:
            if len(row) < 5:
                continue
            try:
                rid = int(row[0])
            except ValueError:
                continue
            highest = max(highest, rid)
            domain = row[4]
            if not any(p.search(domain.lower()) for p in patterns):
                continue
            host = row[3] if row[3] else "-"
            log.write("%s\t%s\t%s\t%s\n" % (_iso(row[1]), row[2], host, domain))
            hits += 1
    if highest > cursor:
        CURSOR.write_text(str(highest))
    print("ca-tripwire: examined through id %d, logged %d hit(s)" % (highest, hits))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
