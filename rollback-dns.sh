#!/usr/bin/env bash
# Put this machine back on Cloudflare/Google DNS without touching Pi-hole files.
set -euo pipefail
# Go build if present (go/bin/rollback-dns); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/rollback-dns"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need WIFI_CON "${HINT_WIFI_CON}"
need WIFI_DEV "${HINT_WIFI_DEV}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as: sudo $0" >&2
  exit 1
fi

nmcli connection modify "${WIFI_CON}" \
  ipv4.dns "1.1.1.1,8.8.8.8" \
  ipv6.dns "2606:4700:4700::1111,2001:4860:4860::8888" \
  ipv4.ignore-auto-dns yes \
  ipv6.ignore-auto-dns yes

if ! nmcli device reapply "${WIFI_DEV}"; then
  resolvectl dns "${WIFI_DEV}" 1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888
fi

echo "DNS restored to 1.1.1.1 / 8.8.8.8."
getent hosts example.com || true
