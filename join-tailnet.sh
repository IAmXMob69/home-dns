#!/usr/bin/env bash
# Bring this host onto the tailnet WITHOUT using Tailscale DNS.
# Using Tailscale DNS here would make Pi-hole the host's resolver via 100.x
# and can loop. Unbound remains Pi-hole's recursive upstream.
set -euo pipefail
# Go build if present (go/bin/join-tailnet); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/join-tailnet"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"

if ! command -v tailscale >/dev/null 2>&1; then
  echo "Install Tailscale first: sudo ${PIHOLE_DIR}/setup-tailscale-privileged.sh" >&2
  exit 1
fi

# Persist accept-dns=false even if a later `tailscale up` forgets the flag.
# TS_OPERATOR defaults to this login; TS_HOSTNAME empty keeps the OS hostname.
up=(tailscale up --accept-dns=false --advertise-exit-node)
operator="$(setting TS_OPERATOR "${USER:-}")"
hostname_ts="$(setting TS_HOSTNAME)"
[[ -n "${operator}" ]] && up+=("--operator=${operator}")
[[ -n "${hostname_ts}" ]] && up+=("--hostname=${hostname_ts}")
"${up[@]}" "$@"
tailscale set --accept-dns=false
tailscale set --advertise-exit-node
echo
tailscale status || true
echo
echo "This host Tailscale IPv4: $(tailscale ip -4 2>/dev/null || echo '(not logged in yet)')"
echo "Admin DNS next: https://login.tailscale.com/admin/dns"
echo "  Global nameserver = that 100.x address"
echo "  Enable Override local DNS"
