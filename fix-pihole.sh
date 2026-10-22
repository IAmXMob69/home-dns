#!/usr/bin/env bash
# Safe Pi-hole bring-up for Arch + systemd-resolved.
# Never points this machine at Pi-hole until 127.0.0.1:53 answers.
set -euo pipefail
# Go build if present (go/bin/fix-pihole); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/fix-pihole"
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

restore_host_dns() {
  echo "==> Restoring Cloudflare/Google DoT on ${WIFI_CON}"
  failover_public_dns || true
}

fail() {
  echo "ERROR: $*" >&2
  restore_host_dns
  exit 1
}

echo "==> Installing/starting Docker"
pacman -S --needed --noconfirm docker docker-compose
systemctl enable --now docker
usermod -aG docker "${USER_NAME}" || true

echo "==> Stopping the old host-network Pi-hole (it could not bind port 53)"
cd "${PIHOLE_DIR}"
docker compose down --remove-orphans || true

echo "==> Disabling systemd-resolved's stub listener on port 53"
rm -f /etc/systemd/resolved.conf.d/fix.conf
install -d /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/no-stub.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
chmod 644 /etc/systemd/resolved.conf.d/no-stub.conf
ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl daemon-reload
systemctl stop systemd-resolved
sleep 1
systemctl start systemd-resolved
sleep 1

if ss -tuln | grep -q '127.0.0.53'; then
  echo "WARNING: 127.0.0.53 is still present; continuing with 127.0.0.1-only Docker ports"
else
  echo "systemd-resolved stub is gone"
fi

echo "==> Checking internet still works via 1.1.1.1"
"${PROBE[@]}" example.com 1.1.1.1 || fail "Cloudflare DNS stopped answering"

echo "==> Starting Pi-hole on 127.0.0.1:53"
install -d -o "${USER_NAME}" -g "${USER_NAME}" "${PIHOLE_DIR}/etc-pihole"
docker compose up -d

echo "==> Waiting for Pi-hole DNS on 127.0.0.1:53"
ready=0
for _ in $(seq 1 30); do
  if "${PROBE[@]}" example.com 127.0.0.1 >/tmp/pihole-dns-probe.log 2>&1; then
    cat /tmp/pihole-dns-probe.log
    ready=1
    break
  fi
  sleep 2
done
if [[ ${ready} -ne 1 ]]; then
  echo "Pi-hole DNS did not answer. Last probe:" >&2
  cat /tmp/pihole-dns-probe.log >&2 || true
  docker compose logs --tail 100
  fail "refusing to point this machine at a dead resolver"
fi

echo "==> Confirming Pi-hole answers a block-list domain"
"${PROBE[@]}" doubleclick.net 127.0.0.1 || fail "Pi-hole did not answer a block-list query"

if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi 'Status: active'; then
  echo "==> Allowing the web UI through UFW (DNS is loopback-only)"
  ufw allow 80/tcp comment 'Pi-hole web' || true
  ufw allow 443/tcp comment 'Pi-hole web TLS' || true
fi

echo "==> Pointing this machine at Pi-hole DoT"
restore_pihole_dns
sleep 2

echo "==> Checking the full resolver path"
if ! getent hosts example.com >/tmp/pihole-getent.log; then
  cat /tmp/pihole-getent.log >&2 || true
  fail "hostname lookup still broken after switching DNS"
fi
cat /tmp/pihole-getent.log
"${PROBE[@]}" example.com 127.0.0.1 || fail "Pi-hole stopped answering after the DNS switch"

echo
echo "Pi-hole is up and this machine's DNS is using it."
echo "Dashboard: http://127.0.0.1/admin/"
echo "Password is in ${PIHOLE_DIR}/.env"
echo "If lookups break: sudo ${PIHOLE_DIR}/rollback-dns.sh"
