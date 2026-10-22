#!/usr/bin/env bash
# Adapted from webpwnized/pihole-automation status.sh for this Docker host.
set -euo pipefail
# Go build if present (go/bin/status); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/status"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "==============================="
echo " Pi-hole automation status"
echo "==============================="
echo
echo "Host: $(uname -srm)"
echo "Pi-hole dir: ${ROOT}"
echo
echo "Containers:"
# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"
docker_cmd compose -f "${ROOT}/docker-compose.yml" -f "${ROOT}/docker-compose.tailscale.yml" --env-file "${ROOT}/.env" ps 2>/dev/null \
  || docker compose -f "${ROOT}/docker-compose.yml" ps 2>/dev/null \
  || echo "(docker not available in this session)"
echo
echo "Pi-hole version (container):"
docker_cmd exec pihole pihole -v 2>/dev/null || docker exec pihole pihole -v 2>/dev/null || echo "(cannot exec pihole)"
echo
echo "Watchdog state:"
if [[ -f "${ROOT}/state/watchdog.json" ]]; then
  cat "${ROOT}/state/watchdog.json"
  echo
else
  echo "(missing)"
fi
echo
echo "Health state:"
if [[ -f "${ROOT}/state/health.json" ]]; then
  cat "${ROOT}/state/health.json"
  echo
else
  echo "(missing — run healthcheck.sh)"
fi
echo
echo "Last gravity:"
if [[ -f "${ROOT}/state/last-gravity.json" ]]; then
  cat "${ROOT}/state/last-gravity.json"
  echo
else
  gravity="$(sqlite3 "${ROOT}/etc-pihole/gravity.db" "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" 2>/dev/null || echo "?")"
  echo "gravity_count=${gravity} (no last-gravity.json yet)"
fi
echo
echo "gravity_count (live):"
sqlite3 "${ROOT}/etc-pihole/gravity.db" "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" 2>/dev/null \
  || docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" 2>/dev/null \
  || echo "(unavailable)"
echo
echo "Timers (pihole-*):"
systemctl --user list-timers 'pihole-*' --no-pager 2>/dev/null || systemctl --user list-timers --no-pager 2>/dev/null | grep pihole || true
echo
echo "cleanup.log (tail):"
if [[ -f "${ROOT}/logs/cleanup.log" ]]; then
  tail -n 15 "${ROOT}/logs/cleanup.log"
else
  echo "not created yet"
fi
echo
echo "Logs:"
for log in "${ROOT}/logs/update-gravity.log" "${ROOT}/logs/update-pihole.log" "${ROOT}/logs/healthcheck.log" "${ROOT}/logs/watchdog.log"; do
  echo
  echo "==> ${log}"
  if [[ -f ${log} ]]; then
    tail -n 8 "${log}"
  else
    echo "not created yet"
  fi
done
echo
echo "Adlists: $(python3 - "${ROOT}/etc-pihole/gravity.db" <<'PY'
import sqlite3, sys
c=sqlite3.connect(sys.argv[1])
print(c.execute('select count(*) from adlist where enabled=1').fetchone()[0], 'enabled')
PY
)"
