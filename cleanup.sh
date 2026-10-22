#!/usr/bin/env bash
# Drop Pi-hole junk that rebuilds itself (old gravity copies, debug logs, extra backups).
# Does not delete gravity.db or listsCache — those are the working blocklists.
set -euo pipefail
# Go build if present (go/bin/cleanup); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/cleanup"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG="${ROOT}/logs/cleanup.log"
mkdir -p "${ROOT}/logs"
exec >>"${LOG}" 2>&1

# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"

echo "[$(date)] cleanup start"

# Keep gravity.db, gravity_old.db, and listsCache. Those are the listed domains.

# Debug dumps and probe leftovers. Ignore root-owned leftovers from sudo probes.
find /tmp -maxdepth 1 -user "$(id -un)" \( -name 'pihole-*.log' -o -name 'pihole-*.html' \) -delete 2>/dev/null || true

# Probe once via docker_cmd (never bare sudo docker / docker info). Skip container
# work cleanly when the user session lacks an active docker group and has no
# passwordless sudo — docker_cmd itself never prompts.
DOCKER_OK=0
if docker_cmd info >/dev/null 2>&1; then
  DOCKER_OK=1
else
  echo "[$(date)] WARN: docker unavailable via docker_cmd; skipping container cleanup"
fi

if [[ "${DOCKER_OK}" -eq 1 ]]; then
  docker_cmd exec pihole rm -f /var/log/pihole/pihole_debug.log /var/log/pihole/pihole_updateGravity.log 2>/dev/null || true

  # Rotate query/FTL logs inside the container (Alpine image crontab may skip periodic/).
  if docker_cmd exec pihole test -x /usr/sbin/logrotate 2>/dev/null; then
    docker_cmd exec pihole logrotate /etc/logrotate.d/pihole || true
  fi

  docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
fi

# Checkpoint the query WAL (host bind-mount; FTL keeps it open).
if command -v sqlite3 >/dev/null 2>&1 && [[ -f "${ROOT}/etc-pihole/pihole-FTL.db" ]]; then
  sqlite3 "${ROOT}/etc-pihole/pihole-FTL.db" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
fi

# Orphan list cache files (lists no longer in gravity.db).
python3 - "${ROOT}/etc-pihole" <<'PY'
import re, sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
cache = root / "listsCache"
db = root / "gravity.db"
if not cache.is_dir() or not db.is_file():
    raise SystemExit(0)
ids = {r[0] for r in sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute("SELECT id FROM adlist")}
removed = 0
bytes_ = 0
for p in cache.iterdir():
    m = re.match(r"list\.(\d+)\.", p.name)
    if not m or int(m.group(1)) in ids:
        continue
    bytes_ += p.stat().st_size
    p.unlink()
    removed += 1
if removed:
    print(f"removed {removed} orphan cache files ({bytes_} bytes)")
PY

# Keep 3 newest config backups only.
if [[ -d "${ROOT}/backups" ]]; then
  # shellcheck disable=SC2012 # names are our own timestamps
  mapfile -t old < <(ls -1t "${ROOT}/backups"/pihole-* 2>/dev/null | tail -n +4 || true)
  if ((${#old[@]})); then
    rm -f "${old[@]}"
    echo "pruned extra backups"
  fi
fi

# Cap automation logs at 1 MiB.
for f in "${ROOT}/logs"/*.log; do
  [[ -f "${f}" ]] || continue
  if [[ "$(stat -c%s "${f}")" -gt 1048576 ]]; then
    tail -c 262144 "${f}" >"${f}.tmp" && mv "${f}.tmp" "${f}"
  fi
done

# Dangling Docker images only (never -a: that would delete in-use tags).
if [[ "${DOCKER_OK}" -eq 1 ]]; then
  docker_cmd image prune -f >/dev/null || true
fi

echo "[$(date)] pihole dir $(du -sh "${ROOT}" | awk '{print $1}') gravity.db=$(du -sh "${ROOT}/etc-pihole/gravity.db" | awk '{print $1}') listsCache=$(du -sh "${ROOT}/etc-pihole/listsCache" | awk '{print $1}')"
df -hP "${ROOT}" | awk 'NR==2{print "[df] "$4" free on "$6" ("$5" used)"}'
echo "[$(date)] cleanup done"
