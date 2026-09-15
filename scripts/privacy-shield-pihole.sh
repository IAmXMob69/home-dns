#!/usr/bin/env bash
# Load telemetry/analytics deny rules into a Pi-hole group you can toggle:
# Group management → Groups → Data collection halt
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TSV="$ROOT/privacy-shield/privacy-shield.tsv"
DB="$ROOT/etc-pihole/gravity.db"
if [[ ! -f "$DB" ]]; then
  echo "Start the stack first (./install.sh)." >&2
  exit 1
fi
if [[ ! -f "$TSV" ]]; then
  echo "missing $TSV" >&2
  exit 1
fi
python3 - "$DB" "$TSV" << 'PY'
import sqlite3, sys, time
from pathlib import Path
db, tsv = sys.argv[1], Path(sys.argv[2])
con=sqlite3.connect(db); cur=con.cursor(); now=int(time.time())
name="Data collection halt"
desc="On = block telemetry, analytics, crash-report, and tracker endpoints. Off = those names work again. Use this switch."
cur.execute('SELECT id FROM "group" WHERE name=?', (name,))
row=cur.fetchone()
if row:
    gid=row[0]
    cur.execute('UPDATE "group" SET enabled=1, description=? WHERE id=?', (desc,gid))
else:
    cur.execute('INSERT INTO "group" (enabled,name,date_added,date_modified,description) VALUES (1,?,?,?,?)',
                (name,now,now,desc))
    gid=cur.lastrowid
n=0
for line in tsv.read_text().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    parts=line.split("\t")
    if len(parts)<3:
        continue
    typ, domain, comment = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if typ not in ("1","3"):
        continue
    cur.execute("SELECT id FROM domainlist WHERE domain=?", (domain,))
    r=cur.fetchone()
    cmt="privacy-shield: "+comment
    if r:
        did=r[0]
        cur.execute("UPDATE domainlist SET type=?, enabled=1, comment=?, date_modified=? WHERE id=?",
                    (int(typ), cmt, now, did))
    else:
        cur.execute("INSERT INTO domainlist (type,domain,enabled,date_added,date_modified,comment) VALUES (?,?,1,?,?,?)",
                    (int(typ), domain, now, now, cmt))
        did=cur.lastrowid
    cur.execute("DELETE FROM domainlist_by_group WHERE domainlist_id=?", (did,))
    cur.execute("INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?,?)", (did,gid))
    n+=1
for ip, comment in [
    ("0.0.0.0/0","All IPv4 devices"),
    ("::/0","All IPv6 devices"),
    ("127.0.0.1","This computer"),
    ("::1","This computer IPv6"),
    ("192.168.0.0/16","Typical home LAN"),
    ("172.16.0.0/12","Private LAN / Docker"),
]:
    cur.execute("SELECT id FROM client WHERE ip=?", (ip,))
    r=cur.fetchone()
    if r:
        cid=r[0]
    else:
        cur.execute("INSERT INTO client (ip,date_added,date_modified,comment) VALUES (?,?,?,?)", (ip,now,now,comment))
        cid=cur.lastrowid
    for g in (0, gid):
        cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?,?)", (cid,g))
con.commit(); con.close()
print("Data collection halt group id", gid, "rules", n)
PY
docker exec pihole pihole reloaddns >/dev/null 2>&1 || true
echo "In Pi-hole: Group management → Groups → Data collection halt"
