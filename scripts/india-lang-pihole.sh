#!/bin/bash
# Add the India language regex (geolock/pihole/india-lang-regex.txt) to Pi-hole.
# Idempotent: entries already present are skipped. --dry-run prints only.
# Undo: Pi-hole admin -> Domains, delete entries commented "india-lang IDN TLDs".
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIST="$ROOT/geolock/pihole/india-lang-regex.txt"
CONTAINER="${PIHOLE_CONTAINER:-pihole}"
COMMENT="india-lang IDN TLDs"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

existing="$(docker exec "$CONTAINER" pihole-FTL sqlite3 -readonly /etc/pihole/gravity.db \
  "SELECT domain FROM domainlist WHERE type = 3;")"
added=0
while IFS= read -r re; do
  case "$re" in ''|'#'*) continue ;; esac
  if grep -qxF -- "$re" <<<"$existing"; then
    echo "present: $re"
    continue
  fi
  if [ "$DRY" = 1 ]; then
    echo "would add: $re"
  else
    docker exec "$CONTAINER" pihole --regex -q "$re" --comment "$COMMENT"
    echo "added: $re"
  fi
  added=$((added + 1))
done < "$LIST"
echo "india-lang: $added new regex entr$([ "$added" = 1 ] && echo y || echo ies)"
