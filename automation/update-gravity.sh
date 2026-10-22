#!/usr/bin/env bash
# Adapted from webpwnized/pihole-automation for Docker Pi-hole.
set -euo pipefail
# Go build if present (go/bin/update-gravity); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/update-gravity"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${ROOT}/logs/update-gravity.log"
STATE_DIR="${ROOT}/state"
mkdir -p "${ROOT}/logs" "${STATE_DIR}"
exec >>"${LOG}" 2>&1
# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"

notify_desktop() {
  local title="$1" body="$2"
  DISPLAY=:0.0 DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}" \
    notify-send -a Pi-hole "${title}" "${body}" >/dev/null 2>&1 || true
}

# After pihole -g, ensure Default group links exist when gravity wiped them.
restore_group_links() {
  local counts ad_bg dl_bg enabled_ad enabled_dl
  counts="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "SELECT COUNT(*) FROM adlist_by_group; SELECT COUNT(*) FROM domainlist_by_group;" \
    || true)"
  ad_bg="$(printf '%s\n' "${counts}" | sed -n '1p')"
  dl_bg="$(printf '%s\n' "${counts}" | sed -n '2p')"
  ad_bg="${ad_bg//$'\r'/}"; ad_bg="${ad_bg:-0}"
  dl_bg="${dl_bg//$'\r'/}"; dl_bg="${dl_bg:-0}"

  enabled_ad="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "SELECT COUNT(*) FROM adlist WHERE enabled=1;" || echo 0)"
  enabled_dl="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "SELECT COUNT(*) FROM domainlist WHERE enabled=1;" || echo 0)"
  enabled_ad="${enabled_ad//$'\r'/}"; enabled_ad="${enabled_ad%%$'\n'*}"; enabled_ad="${enabled_ad:-0}"
  enabled_dl="${enabled_dl//$'\r'/}"; enabled_dl="${enabled_dl%%$'\n'*}"; enabled_dl="${enabled_dl:-0}"

  if [[ "${ad_bg}" -eq 0 && "${enabled_ad}" -gt 0 ]] || \
     [[ "${dl_bg}" -eq 0 && "${enabled_dl}" -gt 0 ]]; then
    echo "[$(date)] WARN: group links missing (adlist_by_group=${ad_bg} domainlist_by_group=${dl_bg}); restoring to Default (0)"
    docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "
INSERT OR IGNORE INTO \"group\" (id, enabled, name) VALUES (0, 1, 'Default');
INSERT OR IGNORE INTO adlist_by_group (adlist_id, group_id) SELECT id, 0 FROM adlist;
INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) SELECT id, 0 FROM domainlist;
"
    docker_cmd exec pihole pihole reloaddns
    counts="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
      "SELECT COUNT(*) FROM adlist_by_group; SELECT COUNT(*) FROM domainlist_by_group;" \
      || true)"
    ad_bg="$(printf '%s\n' "${counts}" | sed -n '1p')"
    dl_bg="$(printf '%s\n' "${counts}" | sed -n '2p')"
    ad_bg="${ad_bg//$'\r'/}"; ad_bg="${ad_bg:-0}"
    dl_bg="${dl_bg//$'\r'/}"; dl_bg="${dl_bg:-0}"
    echo "[$(date)] restored group links: adlist_by_group=${ad_bg} domainlist_by_group=${dl_bg}"
  else
    echo "[$(date)] group links ok: adlist_by_group=${ad_bg} domainlist_by_group=${dl_bg}"
  fi

  # Export for caller / state file
  ADLIST_BY_GROUP="${ad_bg}"
  DOMAINLIST_BY_GROUP="${dl_bg}"
}

avail_kb="$(df -Pk "${ROOT}/etc-pihole" | awk 'NR==2{print $4}')"
# Gravity swap needs old DB + new temp DB. Abort rather than fill the disk.
if [[ "${avail_kb}" -lt 8388608 ]]; then
  echo "[$(date)] ERROR: only ${avail_kb} KB free; need 8 GB before gravity"
  exit 1
fi
echo "[$(date)] Pi-hole gravity update start (${avail_kb} KB free)"
if docker_cmd exec pihole pihole -g; then
  count="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" || echo 0)"
  count="${count//$'\r'/}"
  count="${count%%$'\n'*}"
  count="${count:-0}"
  echo "[$(date)] SUCCESS: gravity updated (${count} unique list domains)"

  ADLIST_BY_GROUP=0
  DOMAINLIST_BY_GROUP=0
  restore_group_links

  # HaGeZi Pro + AdguardDNS re-inject ||xy.fbcdn.net^ / ||xz.fbcdn.net^ which
  # breaks Facebook iOS/Android profile photos (netseer-ipaddr-assoc).
  echo "[$(date)] stripping Facebook CDN gravity + ensuring antigravity allow"
  docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "
DELETE FROM gravity WHERE domain IN (
  'xy.fbcdn.net','xz.fbcdn.net','||xy.fbcdn.net^','||xz.fbcdn.net^'
);
INSERT OR IGNORE INTO antigravity (domain, adlist_id)
SELECT domain, (SELECT id FROM adlist WHERE address='file:///etc/pihole/allow-facebook.txt' LIMIT 1)
FROM (
  SELECT '||facebook.com^' AS domain UNION ALL SELECT '||fb.com^' UNION ALL
  SELECT '||fbcdn.net^' UNION ALL SELECT '||xy.fbcdn.net^' UNION ALL
  SELECT '||xz.fbcdn.net^' UNION ALL SELECT '||facebook.net^' UNION ALL
  SELECT '||messenger.com^' UNION ALL SELECT '||fbsbx.com^' UNION ALL
  SELECT '||meta.com^' UNION ALL SELECT '||instagram.com^' UNION ALL
  SELECT '||cdninstagram.com^'
) d
WHERE (SELECT id FROM adlist WHERE address='file:///etc/pihole/allow-facebook.txt' LIMIT 1) IS NOT NULL;
"
  docker_cmd exec pihole pihole reloaddns || true

  python3 -c '
import json, sys
from pathlib import Path
from datetime import datetime, timezone
count = int(sys.argv[1])
ad_bg = int(sys.argv[2])
dl_bg = int(sys.argv[3])
path = Path(sys.argv[4])
path.write_text(json.dumps({
    "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
    "gravity_count": count,
    "adlist_by_group": ad_bg,
    "domainlist_by_group": dl_bg,
}, separators=(",", ":")))
' "${count}" "${ADLIST_BY_GROUP}" "${DOMAINLIST_BY_GROUP}" "${STATE_DIR}/last-gravity.json"

  if [[ "${count}" -lt 100000 ]]; then
    echo "[$(date)] ERROR: gravity_count ${count} < 100000"
    notify_desktop "Pi-hole gravity low" "gravity_count=${count} (need >= 100000)"
    exit 1
  fi
else
  echo "[$(date)] ERROR: gravity update failed"
  notify_desktop "Pi-hole gravity failed" "pihole -g returned non-zero"
  exit 1
fi
