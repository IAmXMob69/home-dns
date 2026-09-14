#!/usr/bin/env bash
# Install Geo-Location Lock as a Pi-hole *group* so it shows in the admin UI
# (Group management → Groups) and can be flipped on/off.
# Does not touch adlists, passwords, or your gravity allowlist.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LISTS="$ROOT/geolock/pihole"
DB_HOST="$ROOT/etc-pihole/gravity.db"

if [[ ! -f "$DB_HOST" ]]; then
  echo "No etc-pihole/gravity.db yet. Start the stack first (./install.sh or .\\install.ps1)." >&2
  exit 1
fi

python3 - "$DB_HOST" "$LISTS" << 'PY'
import sqlite3, sys, time
from pathlib import Path

db, lists = sys.argv[1], Path(sys.argv[2])
con = sqlite3.connect(db)
cur = con.cursor()
now = int(time.time())

cur.execute('SELECT id FROM "group" WHERE name=?', ("Geo-Location Lock",))
row = cur.fetchone()
desc = (
    "On = block India, Africa, Israel, and Saudi names (ccTLDs and major sites). "
    "Off = those sites work again. Use this switch; do not delete the domains."
)
if row:
    gid = row[0]
    cur.execute('UPDATE "group" SET enabled=1, description=? WHERE id=?', (desc, gid))
else:
    cur.execute(
        'INSERT INTO "group" (enabled, name, date_added, date_modified, description) VALUES (1, ?, ?, ?, ?)',
        ("Geo-Location Lock", now, now, desc),
    )
    gid = cur.lastrowid

def upsert_domain(dtype, domain, comment):
    cur.execute("SELECT id FROM domainlist WHERE domain=?", (domain,))
    r = cur.fetchone()
    if r:
        did = r[0]
        cur.execute(
            "UPDATE domainlist SET type=?, enabled=1, comment=?, date_modified=? WHERE id=?",
            (dtype, comment, now, did),
        )
    else:
        cur.execute(
            "INSERT INTO domainlist (type, domain, enabled, date_added, date_modified, comment) VALUES (?, ?, 1, ?, ?, ?)",
            (dtype, domain, now, now, comment),
        )
        did = cur.lastrowid
    cur.execute("DELETE FROM domainlist_by_group WHERE domainlist_id=?", (did,))
    cur.execute(
        "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
        (did, gid),
    )

# type 3 = regex deny, type 1 = exact deny
for line in (lists / "regex.txt").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    upsert_domain(3, line, "Geo lock ccTLD")

files = {
    "domains-india.txt": "Geo lock India domain",
    "domains-africa.txt": "Geo lock Africa domain",
    "domains-israel.txt": "Geo lock Israel domain",
    "domains-saudi.txt": "Geo lock Saudi domain",
}
for fn, comment in files.items():
    p = lists / fn
    if not p.exists():
        continue
    for line in p.read_text().splitlines():
        d = line.strip().lower()
        if not d or d.startswith("#"):
            continue
        upsert_domain(1, d, comment)

clients = [
    ("0.0.0.0/0", "All IPv4 devices — so the group switch applies house-wide"),
    ("::/0", "All IPv6 devices"),
    ("127.0.0.1", "This computer"),
    ("::1", "This computer IPv6"),
    ("192.168.0.0/16", "Typical home LAN"),
    ("10.0.0.0/8", "Private LAN"),
    ("172.16.0.0/12", "Private LAN / Docker"),
]
for ip, comment in clients:
    cur.execute("SELECT id FROM client WHERE ip=?", (ip,))
    r = cur.fetchone()
    if r:
        cid = r[0]
    else:
        cur.execute(
            "INSERT INTO client (ip, date_added, date_modified, comment) VALUES (?, ?, ?, ?)",
            (ip, now, now, comment),
        )
        cid = cur.lastrowid
    for g in (0, gid):
        cur.execute(
            "INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?, ?)",
            (cid, g),
        )

con.commit()
con.close()
print("Geo-Location Lock group id", gid)
PY

if docker exec pihole pihole reloaddns >/dev/null 2>&1; then
  echo "Pi-hole lists reloaded."
else
  echo "Lists written. If Pi-hole is running, run: docker exec pihole pihole reloaddns"
fi
echo
echo "In the Pi-hole page (http://127.0.0.1/admin/) sign in, then:"
echo "  Group management → Groups → Geo-Location Lock"
echo "Flip that switch to turn the lock on or off."
