#!/usr/bin/env bash
# Root helper: Tailscale package, UFW, DOCKER-USER, systemd republish unit.
# Does NOT point this machine at Tailscale/Pi-hole as a DNS loop.
# Usage: sudo ./setup-tailscale-privileged.sh (from the checkout)
set -euo pipefail
# Go build if present (go/bin/setup-tailscale-privileged); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/setup-tailscale-privileged"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need_owner
need LAN_CIDR "It is your LAN network, e.g. 192.168.1.0/24."

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as: sudo $0" >&2
  exit 1
fi

USER_HOME="$(getent passwd "${USER_NAME}" | cut -d: -f6)"
USER_HOME="${USER_HOME:-${PIHOLE_DIR}}"
UNIT=/etc/systemd/system/pihole-tailscale-dns.service

echo "==> Installing Tailscale (extra) and bind (dig). Not enabling named."
pacman -S --needed --noconfirm tailscale bind
systemctl disable --now named.service 2>/dev/null || true

echo "==> Enabling tailscaled (kernel wireguard, tailscale0)"
systemctl enable --now tailscaled

# Operator so that login can run tailscale without root after this.
tailscale set --operator="${USER_NAME}" 2>/dev/null || true

echo "==> UFW: UDP/TCP 53 on tailscale0 only. Never 53 from the WAN."
if command -v ufw >/dev/null 2>&1; then
  ufw --force delete allow 53/tcp >/dev/null 2>&1 || true
  ufw --force delete allow 53/udp >/dev/null 2>&1 || true
  # Direct connections; DNS still does not go to the WAN.
  ufw allow 41641/udp comment 'Tailscale WireGuard' || true
  ufw allow in on tailscale0 to any port 53 proto tcp comment 'Pi-hole DNS Tailscale' || true
  ufw allow in on tailscale0 to any port 53 proto udp comment 'Pi-hole DNS Tailscale' || true
  ufw allow in on tailscale0 to any port 443 proto tcp comment 'Tailscale Serve HTTPS' || true
fi

echo "==> DOCKER-USER: allow Tailscale CGNAT, drop everything else (no WAN 53)"
LAN_CIDR="${LAN_CIDR}" python3 - <<'PY'
import os
from pathlib import Path

lan = os.environ["LAN_CIDR"]
v4 = f"""# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s {lan} -j RETURN
-A DOCKER-USER -s 127.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 100.64.0.0/10 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user
"""
v6 = """# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ::1 -j RETURN
-A DOCKER-USER -s fe80::/10 -j RETURN
-A DOCKER-USER -s fd00::/8 -j RETURN
-A DOCKER-USER -s fd7a:115c:a1e0::/48 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user
"""

def upsert(path: Path, block: str) -> None:
    text = path.read_text()
    begin, end = "# BEGIN pihole-docker-user", "# END pihole-docker-user"
    if begin in text and end in text:
        pre = text[: text.index(begin)]
        post = text[text.index(end) + len(end) :]
        path.write_text(pre + block + post.lstrip("\n"))
    else:
        path.write_text(text.rstrip() + "\n\n" + block)

upsert(Path("/etc/ufw/after.rules"), v4)
upsert(Path("/etc/ufw/after6.rules"), v6)
PY

if iptables -nL DOCKER-USER >/dev/null 2>&1; then
  iptables -F DOCKER-USER
  iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  iptables -A DOCKER-USER -s "${LAN_CIDR}" -j RETURN
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
  ip6tables -A DOCKER-USER -i lo -j RETURN
  ip6tables -A DOCKER-USER -i tailscale0 -j RETURN
  ip6tables -A DOCKER-USER -j DROP
fi

if command -v ufw >/dev/null 2>&1; then
  ufw reload >/dev/null
fi

echo "==> systemd: republish Pi-hole on Tailscale IP after boot"
cat > "${UNIT}" <<EOF
[Unit]
Description=Publish Pi-hole DNS on Tailscale IPv4
After=tailscaled.service docker.service
Wants=tailscaled.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=${USER_NAME}
Group=${USER_NAME}
SupplementaryGroups=docker
Environment=HOME=${USER_HOME}
Environment=USER=${USER_NAME}
WorkingDirectory=${PIHOLE_DIR}
ExecStart=${PIHOLE_DIR}/publish-tailscale-dns.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable pihole-tailscale-dns.service

echo "==> Not changing this host's DNS (keep 127.0.0.1 -> Pi-hole -> Unbound)."
echo "    Tailscale on this host MUST stay: tailscale up --accept-dns=false"
echo "Privileged setup done."
