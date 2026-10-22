#!/usr/bin/env bash
# Lock Pi-hole/Unbound/Grafana to this PC + LAN (LAN_CIDR, optional LAN_IPV6_CIDR) + Tailscale. Never bind [::] or 0.0.0.0.
# Does not change the router, Wi-Fi SSID, Linux user, or dashboard passwords.
set -euo pipefail
# Go build if present (go/bin/harden); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/harden"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need_owner
need LAN_CIDR "It is your LAN network, e.g. 192.168.1.0/24."
need LAN_IPV4 "It is this PC's fixed LAN IPv4 address."
LAN_NET="${LAN_CIDR}"
LAN_IPV6_CIDR="$(setting LAN_IPV6_CIDR)"
# Go build if present, else the Python original.
if [[ -x "${PIHOLE_DIR}/go/bin/dns-probe" ]]; then PROBE=("${PIHOLE_DIR}/go/bin/dns-probe"); else PROBE=(python3 "${PIHOLE_DIR}/dns-probe.py"); fi

# shellcheck source=lib/dot-dns.sh
source "${PIHOLE_DIR}/lib/dot-dns.sh"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as: sudo $0" >&2
  exit 1
fi

ensure_docker_user_block() {
  local file="$1"
  local block="$2"
  python3 - "$file" "$block" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
block = sys.argv[2].rstrip() + "\n"
text = path.read_text()
begin, end = "# BEGIN pihole-docker-user", "# END pihole-docker-user"
if begin in text and end in text:
    pre = text[: text.index(begin)]
    post = text[text.index(end) + len(end) :]
    path.write_text(pre + block + post.lstrip("\n"))
else:
    path.write_text(text.rstrip() + "\n\n" + block)
PY
}

echo "==> Tightening secret and config permissions"
chmod 700 "${PIHOLE_DIR}"
chmod 600 "${PIHOLE_DIR}/.env" "${PIHOLE_DIR}/docker-compose.yml"
chmod 700 "${PIHOLE_DIR}/etc-pihole"
chmod 600 "${PIHOLE_DIR}/etc-pihole/cli_pw" \
          "${PIHOLE_DIR}/etc-pihole/tls.pem" \
          "${PIHOLE_DIR}/etc-pihole/tls.crt" \
          "${PIHOLE_DIR}/etc-pihole/tls_ca.crt" || true
chmod 644 "${PIHOLE_DIR}/unbound/custom.conf.d/"*.conf
chmod 755 "${PIHOLE_DIR}/unbound" "${PIHOLE_DIR}/unbound/custom.conf.d"
chmod 755 "${PIHOLE_DIR}/monitoring" "${PIHOLE_DIR}/monitoring/prometheus"
chmod 644 "${PIHOLE_DIR}/monitoring/prometheus/prometheus.yml"
# Grafana container runs as uid 472; 0700 on these bind-mounts hides the dashboard.
chmod 755 "${PIHOLE_DIR}/monitoring/grafana" \
          "${PIHOLE_DIR}/monitoring/grafana/dashboards" \
          "${PIHOLE_DIR}/monitoring/grafana/provisioning" \
          "${PIHOLE_DIR}/monitoring/grafana/provisioning/dashboards" \
          "${PIHOLE_DIR}/monitoring/grafana/provisioning/datasources"
chmod 644 "${PIHOLE_DIR}/monitoring/grafana/dashboards/"*.json \
          "${PIHOLE_DIR}/monitoring/grafana/provisioning/dashboards/"*.yml \
          "${PIHOLE_DIR}/monitoring/grafana/provisioning/datasources/"*.yml
chown -R "${USER_NAME}:${USER_NAME}" "${PIHOLE_DIR}/.env" "${PIHOLE_DIR}/docker-compose.yml"

echo "==> Temporarily using Cloudflare while published ports recreate"
failover_public_dns

echo "==> Recreating stack with IPv4-only host binds"
cd "${PIHOLE_DIR}"
# Network IPv6 flag cannot be changed in place; recreate the project network.
docker compose down --remove-orphans
docker compose up -d

echo "==> Waiting for Pi-hole DNS on 127.0.0.1"
ready=0
for _ in $(seq 1 40); do
  if "${PROBE[@]}" example.com 127.0.0.1 >/tmp/pihole-harden-probe.log 2>&1; then
    cat /tmp/pihole-harden-probe.log
    ready=1
    break
  fi
  sleep 2
done
if [[ ${ready} -ne 1 ]]; then
  cat /tmp/pihole-harden-probe.log >&2 || true
  docker compose logs --tail 80 pihole
  echo "Keeping Cloudflare DNS because Pi-hole did not come back" >&2
  exit 1
fi

echo "==> Replacing world-open UFW 53/80/443 with LAN-only rules"
if command -v ufw >/dev/null 2>&1; then
  # Delete leftover any-source IPv4/IPv6 Pi-hole rules by number (high → low).
  mapfile -t ufw_nums < <(ufw status numbered | sed -n 's/^\[\s*\([0-9]\+\)\] *\(53\|80\|443\|3000\)\/.*/\1/p' | sort -nr)
  for n in "${ufw_nums[@]:-}"; do
    ufw --force delete "${n}" >/dev/null 2>&1 || true
  done
  ufw allow from "${LAN_NET}" to any port 53 proto tcp comment 'Pi-hole DNS LAN' || true
  ufw allow from "${LAN_NET}" to any port 53 proto udp comment 'Pi-hole DNS LAN' || true
  ufw allow from "${LAN_NET}" to any port 853 proto tcp comment 'Pi-hole DoT LAN' || true
  ufw allow from "${LAN_NET}" to any port 8443 proto tcp comment 'Pi-hole DoH LAN' || true
  if [[ -n "${LAN_IPV6_CIDR}" ]]; then
    ufw allow from "${LAN_IPV6_CIDR}" to any port 53 proto tcp comment 'Pi-hole DNS LAN IPv6' || true
    ufw allow from "${LAN_IPV6_CIDR}" to any port 53 proto udp comment 'Pi-hole DNS LAN IPv6' || true
  fi
  # Admin UI is loopback + Tailscale Serve, not :80 on LAN/WAN.
  ufw allow in on tailscale0 to any port 53 proto tcp comment 'Pi-hole DNS Tailscale' || true
  ufw allow in on tailscale0 to any port 53 proto udp comment 'Pi-hole DNS Tailscale' || true
  ufw allow in on tailscale0 to any port 853 proto tcp comment 'Pi-hole DoT Tailscale' || true
  ufw allow in on tailscale0 to any port 8443 proto tcp comment 'Pi-hole DoH Tailscale' || true
  ufw allow in on tailscale0 to any port 443 proto tcp comment 'Tailscale Serve HTTPS' || true
fi

echo "==> Persisting DOCKER-USER drop for non-LAN sources"
ensure_docker_user_block /etc/ufw/after.rules "# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ${LAN_NET} -j RETURN
-A DOCKER-USER -s 127.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 100.64.0.0/10 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user"

v6_lan=""
if [[ -n "${LAN_IPV6_CIDR}" ]]; then
  v6_lan="-A DOCKER-USER -s ${LAN_IPV6_CIDR} -j RETURN"$'\n'
fi
ensure_docker_user_block /etc/ufw/after6.rules "# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ::1 -j RETURN
-A DOCKER-USER -s fe80::/10 -j RETURN
-A DOCKER-USER -s fd00::/8 -j RETURN
-A DOCKER-USER -s fd7a:115c:a1e0::/48 -j RETURN
${v6_lan}-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user"

# Apply immediately as well as on next ufw reload (DOCKER-USER survives docker).
if iptables -nL DOCKER-USER >/dev/null 2>&1; then
  iptables -F DOCKER-USER
  iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  iptables -A DOCKER-USER -s "${LAN_NET}" -j RETURN
  iptables -A DOCKER-USER -s 127.0.0.0/8 -j RETURN
  iptables -A DOCKER-USER -s 172.16.0.0/12 -j RETURN
  iptables -A DOCKER-USER -s 100.64.0.0/10 -j RETURN
  iptables -A DOCKER-USER -i lo -j RETURN
  iptables -A DOCKER-USER -i tailscale0 -j RETURN
  iptables -A DOCKER-USER -j DROP
fi
if ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
  ip6tables -F DOCKER-USER
  ip6tables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  ip6tables -A DOCKER-USER -s ::1 -j RETURN
  ip6tables -A DOCKER-USER -s fe80::/10 -j RETURN
  ip6tables -A DOCKER-USER -s fd00::/8 -j RETURN
  ip6tables -A DOCKER-USER -s fd7a:115c:a1e0::/48 -j RETURN
  if [[ -n "${LAN_IPV6_CIDR}" ]]; then
    ip6tables -A DOCKER-USER -s "${LAN_IPV6_CIDR}" -j RETURN
  fi
  ip6tables -A DOCKER-USER -i lo -j RETURN
  ip6tables -A DOCKER-USER -i tailscale0 -j RETURN
  ip6tables -A DOCKER-USER -j DROP
fi

if command -v ufw >/dev/null 2>&1; then
  ufw reload >/dev/null
fi

echo "==> Pointing this machine back at Pi-hole DoT"
restore_pihole_dns
sleep 1

echo "==> Verifying binds and DNS"
ss -tuln | grep -E ':53 |:853 |:8443 |:80 |:443 |:3000 |:9090 |:9617 ' || true
"${PROBE[@]}" example.com 127.0.0.1
"${PROBE[@]}" example.com "${LAN_IPV4}"
getent hosts example.com | head -2
echo "Harden complete."
