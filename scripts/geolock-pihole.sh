#!/usr/bin/env bash
# Install Geo-Location Lock as a Pi-hole *group* so it shows in the admin UI
# (Group management → Groups) and can be flipped on/off.
# Goes through the Pi-hole v6 API (never writes gravity.db while FTL runs).
# Only touches deny entries whose comment starts with "Geo lock ". Your own
# allow/deny entries are left alone; geo-lock entries removed from the lists
# here are deleted from Pi-hole too.
#   ./scripts/geolock-pihole.sh [--dry-run]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LISTS="$ROOT/geolock/pihole"

args=(
  --group "Geo-Location Lock"
  --description "On = US-centric lock: Africa (all ccTLDs incl. Nigeria), India, South Asia, Malaysia, Israel, Saudi. Off = those sites work again. Use this switch; do not delete the domains."
  --tag "Geo lock "
  --regex "$LISTS/regex.txt:Geo lock ccTLD"
)
for pair in \
  "india:India" "africa:Africa" "israel:Israel" "saudi:Saudi" \
  "southasia:South Asia" "nigeria:Nigeria" "malaysia:Malaysia"
do
  f="$LISTS/domains-${pair%%:*}.txt"
  [[ -f "$f" ]] && args+=(--exact "$f:Geo lock ${pair#*:} domain")
done

# Go build if present, else the Python original.
if [[ -x "$ROOT/go/bin/pihole-groups" ]]; then GROUPS_TOOL=("$ROOT/go/bin/pihole-groups"); else GROUPS_TOOL=(python3 "$ROOT/scripts/lib/pihole_groups.py"); fi
"${GROUPS_TOOL[@]}" "${args[@]}" "$@"
echo
echo "In the Pi-hole page (http://127.0.0.1/admin/) sign in, then:"
echo "  Group management → Groups → Geo-Location Lock"
echo "Flip that switch to turn the lock on or off."
