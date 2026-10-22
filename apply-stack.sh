#!/usr/bin/env bash
# Bring up Pi-hole + Unbound, curated lists, and verify DNS before switching this PC.
set -euo pipefail
# Go build if present (go/bin/apply-stack); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/apply-stack"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need_owner
# Go build if present, else the Python original.
if [[ -x "${PIHOLE_DIR}/go/bin/dns-probe" ]]; then PROBE=("${PIHOLE_DIR}/go/bin/dns-probe"); else PROBE=(python3 "${PIHOLE_DIR}/dns-probe.py"); fi

# shellcheck source=lib/dot-dns.sh
source "${PIHOLE_DIR}/lib/dot-dns.sh"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as: sudo $0" >&2
  exit 1
fi

chmod 644 "${PIHOLE_DIR}/unbound/custom.conf.d/"*.conf || true

echo "==> Temporarily using Cloudflare while the stack recreates"
failover_public_dns

echo "==> Starting Unbound + Pi-hole"
cd "${PIHOLE_DIR}"
docker compose pull unbound
docker compose up -d

echo "==> Waiting for Unbound (DNSSEC)"
unbound_ready=0
for _ in $(seq 1 40); do
  if docker exec unbound drill-hc @127.0.0.1 dnssec.works >/dev/null 2>&1 \
     || docker exec unbound drill @127.0.0.1 dnssec.works >/dev/null 2>&1; then
    unbound_ready=1
    break
  fi
  sleep 3
done
if [[ ${unbound_ready} -ne 1 ]]; then
  docker compose logs --tail 80 unbound
  echo "ERROR: Unbound did not become healthy" >&2
  exit 1
fi

echo "==> Waiting for Pi-hole on 127.0.0.1"
ready=0
for _ in $(seq 1 40); do
  if "${PROBE[@]}" example.com 127.0.0.1 >/tmp/pihole-stack-probe.log 2>&1; then
    cat /tmp/pihole-stack-probe.log
    ready=1
    break
  fi
  sleep 2
done
if [[ ${ready} -ne 1 ]]; then
  cat /tmp/pihole-stack-probe.log >&2 || true
  docker compose logs --tail 80 pihole
  echo "Keeping Cloudflare DNS because Pi-hole did not come back" >&2
  exit 1
fi

echo "==> Adding quality blocklists (idempotent)"
docker exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "
INSERT INTO adlist (address, enabled, comment)
SELECT 'https://small.oisd.nl/', 1, 'OISD small'
WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = 'https://small.oisd.nl/');
INSERT INTO adlist (address, enabled, comment)
SELECT 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-dnscrypt-blocked-names.txt', 1, 'URLhaus malware names'
WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-dnscrypt-blocked-names.txt');
" || true

echo "==> Updating gravity"
docker exec pihole pihole -g || docker exec pihole /opt/pihole/gravity.sh || true

echo "==> Pointing this machine back at Pi-hole DoT"
restore_pihole_dns
sleep 1
getent hosts example.com | head -2
"${PROBE[@]}" doubleclick.net 127.0.0.1 || true
echo "Stack is live."
