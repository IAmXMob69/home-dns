#!/usr/bin/env bash
# Config-only backup. Never pack gravity.db / listsCache (those are ~2GB and rebuildable).
set -euo pipefail
# Go build if present (go/bin/backup); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/backup"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${ROOT}/backups"
KEEP=3
mkdir -p "${DEST}"
stamp="$(date +%Y%m%d-%H%M%S)"
out="${DEST}/pihole-${stamp}.zip"

# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"

if docker_cmd exec pihole pihole-FTL --teleporter >"${out}" 2>/dev/null && [[ -s "${out}" ]]; then
  echo "Wrote ${out}"
else
  rm -f "${out}"
  tar -C "${ROOT}" -czf "${DEST}/pihole-${stamp}.tar.gz" \
    --exclude='etc-pihole/gravity.db' \
    --exclude='etc-pihole/gravity_old.db' \
    --exclude='etc-pihole/listsCache' \
    --exclude='etc-pihole/pihole-FTL.db' \
    --exclude='etc-pihole/pihole-FTL.db-wal' \
    --exclude='etc-pihole/pihole-FTL.db-shm' \
    --exclude='etc-pihole/gravity_backups' \
    docker-compose.yml .env etc-pihole
  echo "Wrote ${DEST}/pihole-${stamp}.tar.gz"
fi

# Keep the newest KEEP files only.
# shellcheck disable=SC2012 # names are our own timestamps
mapfile -t old < <(ls -1t "${DEST}"/pihole-* 2>/dev/null | tail -n +$((KEEP + 1)) || true)
if ((${#old[@]})); then
  rm -f "${old[@]}"
fi
