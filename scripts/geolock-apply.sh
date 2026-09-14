#!/usr/bin/env bash
# Install or remove table inet geolock for DNS/DoT using ipverse country CIDRs.
# Always accepts loopback, RFC1918, and Tailscale CGNAT (100.64.0.0/10).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVF="$ROOT/geolock/settings.env"
CACHE="$ROOT/geolock/cache"
NFT="$CACHE/geolock.nft"

if [[ ! -f "$ENVF" ]]; then
  echo "Missing $ENVF — copy geolock/settings.env.example first" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a
# strip comments
eval "$(grep -v '^[[:space:]]*#' "$ENVF" | grep -v '^[[:space:]]*$')"
set +a

GEOLOCK_ENABLED="${GEOLOCK_ENABLED:-0}"
GEOLOCK_MODE="${GEOLOCK_MODE:-allow}"
GEOLOCK_ALLOW_COUNTRIES="${GEOLOCK_ALLOW_COUNTRIES:-US,DE}"
GEOLOCK_DENY_COUNTRIES="${GEOLOCK_DENY_COUNTRIES:-}"
GEOLOCK_PORTS="${GEOLOCK_PORTS:-53,853}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run as root: sudo $0" >&2
  exit 1
fi

if [[ "$GEOLOCK_ENABLED" != "1" ]]; then
  nft delete table inet geolock 2>/dev/null || true
  echo "geolock disabled (table removed if present)"
  exit 0
fi

mkdir -p "$CACHE"
codes=""
if [[ "$GEOLOCK_MODE" == "deny" ]]; then
  codes="$GEOLOCK_DENY_COUNTRIES"
else
  codes="$GEOLOCK_ALLOW_COUNTRIES"
fi
codes="$(echo "$codes" | tr '[:lower:],' '[:upper:] ' | xargs)"

fetch_cc() {
  local cc="$1" out="$CACHE/${cc}.v4"
  if [[ -s "$out" ]]; then
    return 0
  fi
  curl -fsSL --max-time 30 \
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/${cc}/ipv4-aggregated.txt" \
    | grep -E '^[0-9]' > "$out" || true
}

for cc in $codes; do
  fetch_cc "$cc"
done

{
  echo '#!/usr/bin/nft -f'
  echo 'destroy table inet geolock'
  echo 'table inet geolock {'
  echo '  set pass4 {'
  echo '    type ipv4_addr'
  echo '    flags interval'
  echo '    auto-merge'
  echo '    elements = {'
  echo '      127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10'
  echo '    }'
  echo '  }'
  echo '  set listed4 {'
  echo '    type ipv4_addr'
  echo '    flags interval'
  echo '    auto-merge'
  echo '    elements = {'
  first=1
  for cc in $codes; do
    f="$CACHE/${cc}.v4"
    [[ -s "$f" ]] || continue
    while read -r cidr; do
      [[ -n "$cidr" ]] || continue
      if [[ $first -eq 1 ]]; then
        printf '      %s' "$cidr"
        first=0
      else
        printf ',\n      %s' "$cidr"
      fi
    done < "$f"
  done
  echo
  echo '    }'
  echo '  }'
  echo '  chain input {'
  echo '    type filter hook input priority filter - 5; policy accept;'
  echo '    ip saddr @pass4 accept'
  ports="$(echo "$GEOLOCK_PORTS" | tr ',' ' ')"
  for p in $ports; do
    if [[ "$GEOLOCK_MODE" == "deny" ]]; then
      echo "    tcp dport $p ip saddr @listed4 drop"
      echo "    udp dport $p ip saddr @listed4 drop"
    else
      echo "    tcp dport $p ip saddr != @listed4 drop"
      echo "    udp dport $p ip saddr != @listed4 drop"
    fi
  done
  echo '  }'
  echo '  chain output {'
  echo '    type filter hook output priority filter - 5; policy accept;'
  echo '    ip daddr @pass4 accept'
  for p in $ports; do
    if [[ "$GEOLOCK_MODE" == "deny" ]]; then
      echo "    tcp dport $p ip daddr @listed4 drop"
      echo "    udp dport $p ip daddr @listed4 drop"
      echo "    tcp sport $p ip daddr @listed4 drop"
      echo "    udp sport $p ip daddr @listed4 drop"
    else
      echo "    ip daddr != @listed4 tcp dport $p drop"
      echo "    ip daddr != @listed4 udp dport $p drop"
    fi
  done
  echo '  }'
  echo '}'
} > "$NFT"

nft -f "$NFT"
echo "geolock applied mode=$GEOLOCK_MODE codes=$codes"
