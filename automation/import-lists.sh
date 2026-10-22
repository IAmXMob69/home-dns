#!/usr/bin/env bash
# Import webpwnized/pihole-automation lists.txt into the running Pi-hole.
set -euo pipefail
# Go build if present (go/bin/import-webpwnized-lists); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/import-webpwnized-lists"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/settings.sh
source "${ROOT}/lib/settings.sh"
LISTS="$(setting IMPORT_LISTS_FILE "${ROOT}/pihole-automation/lists.txt")"
if [[ ! -f "${LISTS}" ]]; then
  echo "import-lists.sh: no list file at ${LISTS}." >&2
  echo "Clone https://github.com/webpwnized/pihole-automation into the checkout (pihole-automation/), or set IMPORT_LISTS_FILE to a file with one adlist URL per line." >&2
  exit 2
fi
SQL="$(mktemp)"
trap 'rm -f "${SQL}"' EXIT

{
  echo "BEGIN;"
  grep -E '^https?://' "${LISTS}" | awk 'NF && !seen[$0]++' | while IFS= read -r url; do
    esc=${url//\'/\'\'}
    echo "INSERT INTO adlist (address, enabled, comment) SELECT '${esc}', 1, 'webpwnized/pihole-automation' WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address='${esc}');"
  done
  echo "SELECT COUNT(*) AS enabled FROM adlist WHERE enabled=1;"
  echo "COMMIT;"
} >"${SQL}"

echo "Importing $(grep -cE '^https?://' "${LISTS}") list URLs..."
docker exec -i pihole pihole-FTL sqlite3 /etc/pihole/gravity.db <"${SQL}"
echo "Done. Updating gravity..."
docker exec pihole pihole -g
