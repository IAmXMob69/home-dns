#!/usr/bin/env python3
"""Import webpwnized/pihole-automation lists.txt into Pi-hole gravity.db."""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(os.environ.get("PIHOLE_ROOT") or Path(__file__).resolve().parent.parent)
LISTS = Path(os.environ.get("IMPORT_LISTS_FILE") or ROOT / "pihole-automation" / "lists.txt")
DB = ROOT / "etc-pihole" / "gravity.db"


def urls() -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in LISTS.read_text().splitlines():
        u = line.strip()
        if u.startswith("http") and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main() -> int:
    if not LISTS.is_file():
        print(
            f"import-lists: no list file at {LISTS}.\n"
            "Clone https://github.com/webpwnized/pihole-automation into the checkout "
            "(pihole-automation/), or set IMPORT_LISTS_FILE to a file with one adlist URL per line.",
            file=sys.stderr,
        )
        return 2
    items = urls()
    con = sqlite3.connect(DB)
    added = 0
    for u in items:
        cur = con.execute(
            """
            INSERT INTO adlist (address, enabled, comment)
            SELECT ?, 1, 'webpwnized/pihole-automation'
            WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = ?)
            """,
            (u, u),
        )
        added += cur.rowcount
    con.commit()
    total = con.execute("SELECT COUNT(*) FROM adlist").fetchone()[0]
    enabled = con.execute("SELECT COUNT(*) FROM adlist WHERE enabled=1").fetchone()[0]
    con.close()
    print(f"lists in file: {len(items)}")
    print(f"newly inserted: {added}")
    print(f"adlists now: {enabled} enabled / {total} total")
    print("Run: docker exec pihole pihole -g")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
