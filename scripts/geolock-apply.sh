#!/usr/bin/env bash
# Install or remove table inet geolock for DNS/DoT using ipverse country CIDRs.
# Always accepts loopback, RFC1918, and Tailscale CGNAT (100.64.0.0/10).
#
#   sudo ./scripts/geolock-apply.sh            apply (refresh lists older than GEOLOCK_MAX_AGE_DAYS)
#   sudo ./scripts/geolock-apply.sh --refresh  re-download every list now
#   GEOLOCK_DRY_RUN=1 ./scripts/geolock-apply.sh   build + nft -c only, no root needed
set -euo pipefail
# Go build if present (go/bin/geolock-apply); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/geolock-apply"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVF="${GEOLOCK_SETTINGS:-$ROOT/geolock/settings.env}"
CACHE="${GEOLOCK_CACHE:-$ROOT/geolock/cache}"
NFT_OUT="$CACHE/geolock.nft"
URL_BASE="${GEOLOCK_URL_BASE:-https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country}"
DRY_RUN="${GEOLOCK_DRY_RUN:-0}"
REFRESH=0
[[ "${1:-}" == "--refresh" ]] && REFRESH=1

die() { echo "geolock: $*" >&2; exit 1; }
# nft -c needs CAP_NET_ADMIN; a throwaway user+net namespace is enough.
nft_check() {
  if [[ "$(id -u)" -eq 0 ]]; then
    nft -c -f "$1"
  else
    unshare -rn nft -c -f "$1"
  fi
}

if [[ ! -f "$ENVF" ]]; then
  die "missing $ENVF. Copy geolock/settings.env.example first."
fi

# Safe KEY=VALUE reader. Nothing in the file is executed.
GEOLOCK_ENABLED=0
GEOLOCK_MODE=allow
GEOLOCK_ALLOW_COUNTRIES=US,DE
GEOLOCK_DENY_COUNTRIES=
GEOLOCK_PORTS=53,853
GEOLOCK_MAX_AGE_DAYS=7
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
  lineno=$((lineno + 1))
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  if [[ ! "$line" =~ ^[[:space:]]*([A-Z_]+)=[\"\']?([A-Za-z0-9,._-]*)[\"\']?[[:space:]]*$ ]]; then
    die "$ENVF:$lineno: expected KEY=value"
  fi
  key="${BASH_REMATCH[1]}" val="${BASH_REMATCH[2]}"
  case "$key" in
    GEOLOCK_ENABLED) [[ "$val" =~ ^[01]$ ]] || die "$key must be 0 or 1"; GEOLOCK_ENABLED="$val" ;;
    GEOLOCK_MODE) [[ "$val" =~ ^(allow|deny)$ ]] || die "$key must be allow or deny"; GEOLOCK_MODE="$val" ;;
    GEOLOCK_ALLOW_COUNTRIES) GEOLOCK_ALLOW_COUNTRIES="$val" ;;
    GEOLOCK_DENY_COUNTRIES) GEOLOCK_DENY_COUNTRIES="$val" ;;
    GEOLOCK_PORTS) [[ "$val" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "$key must be like 53,853"; GEOLOCK_PORTS="$val" ;;
    GEOLOCK_MAX_AGE_DAYS) [[ "$val" =~ ^[0-9]+$ ]] || die "$key must be a number"; GEOLOCK_MAX_AGE_DAYS="$val" ;;
    *) echo "geolock: ignoring unknown key $key" >&2 ;;
  esac
done < "$ENVF"

if [[ "$DRY_RUN" != "1" && "$(id -u)" -ne 0 ]]; then
  die "re-run as root: sudo $0"
fi

if [[ "$GEOLOCK_ENABLED" != "1" ]]; then
  if [[ "$DRY_RUN" != "1" ]]; then
    nft delete table inet geolock 2>/dev/null || true
  fi
  echo "geolock disabled (table removed if present)"
  exit 0
fi

if [[ "$GEOLOCK_MODE" == "deny" ]]; then
  raw_codes="$GEOLOCK_DENY_COUNTRIES"
else
  raw_codes="$GEOLOCK_ALLOW_COUNTRIES"
fi
codes=()
for cc in ${raw_codes//,/ }; do
  cc="${cc,,}"
  [[ "$cc" =~ ^[a-z]{2}$ ]] || die "bad country code '$cc' (use ISO 3166-1 alpha-2)"
  codes+=("$cc")
done
(( ${#codes[@]} > 0 )) || die "no country codes set for mode $GEOLOCK_MODE"
ports="${GEOLOCK_PORTS//,/, }"

mkdir -p "$CACHE"
chmod 755 "$CACHE"

# Download one country. Keeps the last good copy when a download fails.
fetch_cc() {
  local cc="$1" out="$CACHE/$1.v4" tmp
  if [[ $REFRESH -eq 0 && -s "$out" ]] \
    && [[ -z "$(find "$out" -mtime +"$GEOLOCK_MAX_AGE_DAYS" 2>/dev/null)" ]]; then
    return 0
  fi
  tmp="$(mktemp "$CACHE/.$cc.XXXXXX")"
  if curl -fsSL --retry 2 --max-time 60 "$URL_BASE/$cc/ipv4-aggregated.txt" \
      | grep -E '^[0-9]' > "$tmp" \
    && [[ -s "$tmp" ]] \
    && ! grep -qvE '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$tmp"; then
    chmod 644 "$tmp"
    mv -f "$tmp" "$out"
    return 0
  fi
  rm -f "$tmp"
  if [[ -s "$out" ]]; then
    echo "geolock: WARNING ${cc^^} download failed, keeping cached list from $(date -r "$out" '+%F')" >&2
    return 0
  fi
  echo "geolock: ERROR ${cc^^} download failed and there is no cached list" >&2
  return 1
}

failed=0
for cc in "${codes[@]}"; do
  fetch_cc "$cc" || failed=1
done
# Never load a partial list: in allow mode it would cut off whole countries.
[[ $failed -eq 0 ]] || die "not applying; fix the downloads above and re-run"

tmp_nft="$(mktemp "$CACHE/.geolock.XXXXXX.nft")"
trap 'rm -f "$tmp_nft"' EXIT
{
  echo '#!/usr/bin/nft -f'
  # "table; delete table" works on every nft (destroy needs nft >= 1.0.8).
  echo 'table inet geolock'
  echo 'delete table inet geolock'
  echo 'table inet geolock {'
  echo '  set pass4 {'
  echo '    type ipv4_addr'
  echo '    flags interval'
  echo '    auto-merge'
  echo '    elements = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }'
  echo '  }'
  echo '  set listed4 {'
  echo '    type ipv4_addr'
  echo '    flags interval'
  echo '    auto-merge'
  echo '    elements = {'
  for cc in "${codes[@]}"; do
    sed 's/^/      /; s/$/,/' "$CACHE/$cc.v4"
  done
  echo '    }'
  echo '  }'
  echo '  chain input {'
  echo '    type filter hook input priority filter - 5; policy accept;'
  echo '    ip saddr @pass4 accept'
  if [[ "$GEOLOCK_MODE" == "deny" ]]; then
    echo "    meta l4proto { tcp, udp } th dport { $ports } ip saddr @listed4 counter drop"
  else
    echo "    meta l4proto { tcp, udp } th dport { $ports } ip saddr != @listed4 counter drop"
  fi
  echo '  }'
  # Docker-published ports are DNATed in prerouting and then routed to the
  # container, so they cross forward, not input. Match on the original
  # (host) port so this covers Pi-hole :53 and DoT :853 in containers.
  echo '  chain forward {'
  echo '    type filter hook forward priority filter - 5; policy accept;'
  echo '    ip saddr @pass4 accept'
  if [[ "$GEOLOCK_MODE" == "deny" ]]; then
    echo "    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { $ports } ip saddr @listed4 counter drop"
  else
    echo "    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { $ports } ip saddr != @listed4 counter drop"
  fi
  echo '  }'
  echo '  chain output {'
  echo '    type filter hook output priority filter - 5; policy accept;'
  echo '    ip daddr @pass4 accept'
  # Optional host extras (env, off by default; the cgroups must exist):
  #   GEOLOCK_TAILSCALE_UNDERLAY=1  let tailscaled reach any country
  #   GEOLOCK_APP_CGROUP=<path>     allow mode: that cgroup may only reach
  #                                 listed countries, and no IPv6
  if [[ "${GEOLOCK_TAILSCALE_UNDERLAY:-0}" == "1" ]]; then
    echo '    socket cgroupv2 level 2 "system.slice/tailscaled.service" accept comment "tailscale underlay"'
  fi
  if [[ "$GEOLOCK_MODE" == "allow" && -n "${GEOLOCK_APP_CGROUP:-}" ]]; then
    app_cg="${GEOLOCK_APP_CGROUP#/}"
    IFS=/ read -ra _parts <<<"$app_cg"
    app_lvl="${#_parts[@]}"
    echo "    meta nfproto ipv6 socket cgroupv2 level ${app_lvl} \"${app_cg}\" drop"
    echo "    socket cgroupv2 level ${app_lvl} \"${app_cg}\" ip daddr != @listed4 drop"
  fi
  if [[ "$GEOLOCK_MODE" == "deny" ]]; then
    echo "    meta l4proto { tcp, udp } th dport { $ports } ip daddr @listed4 counter drop"
    echo "    meta l4proto { tcp, udp } th sport { $ports } ip daddr @listed4 counter drop"
  else
    echo "    meta l4proto { tcp, udp } th dport { $ports } ip daddr != @listed4 counter drop"
  fi
  echo '  }'
  echo '}'
} > "$tmp_nft"

nft_check "$tmp_nft" || die "generated ruleset failed nft -c; nothing changed"
chmod 644 "$tmp_nft"
mv -f "$tmp_nft" "$NFT_OUT"
trap - EXIT
codes_up="${codes[*]^^}"
if [[ "$DRY_RUN" == "1" ]]; then
  echo "geolock dry run OK: $NFT_OUT mode=$GEOLOCK_MODE codes=$codes_up"
  exit 0
fi
nft -f "$NFT_OUT"
echo "geolock applied mode=$GEOLOCK_MODE codes=$codes_up"
echo "drop counters: nft list table inet geolock | grep counter"
