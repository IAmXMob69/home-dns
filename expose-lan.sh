#!/usr/bin/env bash
# Publish Pi-hole DNS on the LAN and allow it through the firewall (LAN sources only).
set -euo pipefail
# Go build if present (go/bin/expose-lan); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/expose-lan"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need LAN_IPV4 "It is this PC's fixed LAN IPv4 address."
need LAN_CIDR "It is your LAN network, e.g. 192.168.1.0/24."
need LAN_GATEWAY "It is your router's LAN IPv4 address."
LAN_IPV6_CIDR="$(setting LAN_IPV6_CIDR)"
LAN_IP="${LAN_IPV4}"
LAN_PREFIX="${LAN_CIDR#*/}"
[[ "${LAN_PREFIX}" == "${LAN_CIDR}" ]] && LAN_PREFIX=24
# Go build if present, else the Python original.
if [[ -x "${PIHOLE_DIR}/go/bin/dns-probe" ]]; then PROBE=("${PIHOLE_DIR}/go/bin/dns-probe"); else PROBE=(python3 "${PIHOLE_DIR}/dns-probe.py"); fi

# shellcheck source=lib/dot-dns.sh
source "${PIHOLE_DIR}/lib/dot-dns.sh"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as: sudo $0" >&2
  exit 1
fi

echo "==> Keep a stable Wi-Fi MAC/IP so the phone's DNS setting does not go stale"
nmcli connection modify "${WIFI_CON}" \
  wifi.cloned-mac-address permanent \
  ipv4.method manual \
  ipv4.addresses "${LAN_IP}/${LAN_PREFIX}" \
  ipv4.gateway "${LAN_GATEWAY}" \
  ipv4.dns "${PIHOLE_DNS}" \
  connection.dns-over-tls yes \
  ipv4.ignore-auto-dns yes \
  ipv6.ignore-auto-dns yes || true
nmcli device reapply "${WIFI_DEV}" >/dev/null 2>&1 || true

echo "==> Recreating Pi-hole with LAN DNS ports"
cd "${PIHOLE_DIR}"
docker compose up -d

if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi 'Status: active'; then
  echo "==> Allowing DNS/admin from the LAN only (never 0.0.0.0/0 or ::/0)"
  ufw --force delete allow 53/tcp >/dev/null 2>&1 || true
  ufw --force delete allow 53/udp >/dev/null 2>&1 || true
  ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
  ufw --force delete allow 443/tcp >/dev/null 2>&1 || true
  ufw allow from "${LAN_CIDR}" to any port 53 proto tcp comment 'Pi-hole DNS LAN' || true
  ufw allow from "${LAN_CIDR}" to any port 53 proto udp comment 'Pi-hole DNS LAN' || true
  ufw allow from "${LAN_CIDR}" to any port 853 proto tcp comment 'Pi-hole DoT LAN' || true
  ufw allow from "${LAN_CIDR}" to any port 8443 proto tcp comment 'Pi-hole DoH LAN' || true
  if [[ -n "${LAN_IPV6_CIDR}" ]]; then
    ufw allow from "${LAN_IPV6_CIDR}" to any port 53 proto tcp comment 'Pi-hole DNS LAN IPv6' || true
    ufw allow from "${LAN_IPV6_CIDR}" to any port 53 proto udp comment 'Pi-hole DNS LAN IPv6' || true
  fi
fi

echo "==> Waiting for DNS on ${LAN_IP}"
ready=0
for _ in $(seq 1 20); do
  if "${PROBE[@]}" example.com "${LAN_IP}" >/tmp/pihole-lan-probe.log 2>&1; then
    cat /tmp/pihole-lan-probe.log
    ready=1
    break
  fi
  sleep 1
done
if [[ ${ready} -ne 1 ]]; then
  cat /tmp/pihole-lan-probe.log >&2 || true
  docker compose logs --tail 40
  exit 1
fi

ss -tuln | grep ':53 ' || true
echo "Phone DNS server: ${LAN_IP}"
