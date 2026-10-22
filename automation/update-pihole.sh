#!/usr/bin/env bash
# Adapted from webpwnized/pihole-automation (pihole -up) for Docker Compose.
# Temporarily fails over host DNS to Cloudflare during pull/up, then restores.
set -euo pipefail
# Go build if present (go/bin/update-pihole); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/update-pihole"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${ROOT}/logs/update-pihole.log"
# Go build if present, else the Python original.
if [[ -x "${ROOT}/go/bin/dns-probe" ]]; then PROBE=("${ROOT}/go/bin/dns-probe"); else PROBE=(python3 "${ROOT}/dns-probe.py"); fi

# shellcheck source=lib/dot-dns.sh
source "${ROOT}/lib/dot-dns.sh"

mkdir -p "${ROOT}/logs"
exec >>"${LOG}" 2>&1
echo "[$(date)] Docker Pi-hole/Unbound image update start"

# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"
cd "${ROOT}"

echo "[$(date)] Temporarily setting Wi-Fi DNS to Cloudflare DoT"
failover_public_dns

set +e
docker_cmd compose --env-file .env -f docker-compose.yml -f docker-compose.tailscale.yml pull
pull_rc=$?
docker_cmd compose --env-file .env -f docker-compose.yml -f docker-compose.tailscale.yml up -d
up_rc=$?
set -e

if [[ ${pull_rc} -ne 0 || ${up_rc} -ne 0 ]]; then
  echo "[$(date)] ERROR: compose pull/up failed (pull=${pull_rc} up=${up_rc}); leaving Cloudflare DNS"
  exit 1
fi

echo "[$(date)] Waiting for Pi-hole DNS on 127.0.0.1"
ready=0
for _ in $(seq 1 40); do
  if "${PROBE[@]}" example.com 127.0.0.1 >/tmp/pihole-update-probe.log 2>&1; then
    cat /tmp/pihole-update-probe.log
    ready=1
    break
  fi
  sleep 2
done

if [[ ${ready} -ne 1 ]]; then
  cat /tmp/pihole-update-probe.log >&2 || true
  echo "[$(date)] ERROR: Pi-hole did not answer after update; leaving Cloudflare DNS"
  exit 1
fi

echo "[$(date)] Restoring Wi-Fi DNS to Pi-hole DoT"
restore_pihole_dns

echo "[$(date)] SUCCESS: compose pull/up completed; DNS restored to Pi-hole"
docker_cmd compose --env-file .env -f docker-compose.yml -f docker-compose.tailscale.yml ps
