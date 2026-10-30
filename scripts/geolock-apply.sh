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

# shellcheck source=lib/cidr.sh
source "$ROOT/lib/cidr.sh"

NFT="${GEOLOCK_NFT:-nft}"
die() { echo "geolock: $*" >&2; exit 1; }
# nft -c needs CAP_NET_ADMIN; a throwaway user+net namespace is enough.
nft_check() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$NFT" -c -f "$1"
  else
    unshare -rn "$NFT" -c -f "$1"
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
GEOLOCK_IPV6=0
GEOLOCK_INBOUND=1
GEOLOCK_OUTBOUND=1
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
  lineno=$((lineno + 1))
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  if [[ ! "$line" =~ ^[[:space:]]*([A-Z_0-9]+)=[\"\']?([A-Za-z0-9,._-]*)[\"\']?[[:space:]]*$ ]]; then
    die "$ENVF:$lineno: expected KEY=value"
  fi
  key="${BASH_REMATCH[1]}" val="${BASH_REMATCH[2]}"
  case "$key" in
    GEOLOCK_ENABLED|GEOLOCK_IPV6|GEOLOCK_INBOUND|GEOLOCK_OUTBOUND)
      [[ "$val" =~ ^[01]$ ]] || die "$key must be 0 or 1"; printf -v "$key" '%s' "$val" ;;
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
    "$NFT" delete table inet geolock 2>/dev/null || true
  fi
  echo "geolock disabled (table removed if present)"
  exit 0
fi
if [[ "$GEOLOCK_INBOUND" != "1" && "$GEOLOCK_OUTBOUND" != "1" ]]; then
  die "GEOLOCK_INBOUND and GEOLOCK_OUTBOUND are both 0; use GEOLOCK_ENABLED=0 instead"
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
fams=(v4)
[[ "$GEOLOCK_IPV6" == "1" ]] && fams+=(v6)

mkdir -p "$CACHE"
chmod 755 "$CACHE"

# Download one country list (v4 or v6). Keeps the last good copy when a
# download fails.
fetch_cc() {
  local cc="$1" fam="$2" out="$CACHE/$1.$2" tmp what="${1^^}"
  [[ "$fam" == "v6" ]] && what="${cc^^} IPv6"
  # A fresh list is used as is. For IPv6 an empty file is a fresh cached
  # record that the country has no list upstream.
  if [[ $REFRESH -eq 0 && -f "$out" ]] && [[ -s "$out" || "$fam" == "v6" ]] \
    && [[ -z "$(find "$out" -mtime +"$GEOLOCK_MAX_AGE_DAYS" 2>/dev/null)" ]]; then
    return 0
  fi
  tmp="$(mktemp "$CACHE/.$cc.XXXXXX")"
  # Every non-comment line must be a strict prefix of that family
  # (lib/cidr.sh), or the whole download is refused and the cached copy stays.
  local body url="$URL_BASE/$cc/ip${fam}-aggregated.txt"
  if [[ "$fam" == "v6" ]]; then
    # Some countries have no IPv6 allocations, and upstream has no file for
    # them (HTTP 404, or a missing file:// path). Record that as an empty
    # cache file, but never let a 404 replace a good cached list.
    local code rc=0
    code="$(curl -sSL --retry 2 --max-time 60 -o "$tmp" -w '%{http_code}' "$url")" || rc=$?
    if [[ $rc -eq 37 || ( $rc -eq 0 && "$code" == "404" ) ]] && [[ ! -s "$out" ]]; then
      : > "$tmp"
      chmod 644 "$tmp"
      mv -f "$tmp" "$out"
      echo "geolock: note: $what has no list upstream; nothing listed for it" >&2
      return 0
    fi
    if [[ $rc -eq 0 && "$code" =~ ^(200|000)$ ]] && body="$(< "$tmp")" \
      && cidr_filter "$fam" <<<"$body" > "$tmp"; then
      chmod 644 "$tmp"
      mv -f "$tmp" "$out"
      return 0
    fi
  elif body="$(curl -fsSL --retry 2 --max-time 60 "$url")" \
    && cidr_filter "$fam" <<<"$body" > "$tmp"; then
    chmod 644 "$tmp"
    mv -f "$tmp" "$out"
    return 0
  fi
  rm -f "$tmp"
  if [[ -s "$out" ]]; then
    echo "geolock: WARNING $what download failed, keeping cached list from $(date -r "$out" '+%F')" >&2
    return 0
  fi
  if [[ "$fam" == "v6" && -f "$out" ]]; then
    echo "geolock: WARNING $what download failed, keeping the cached no-list record from $(date -r "$out" '+%F')" >&2
    return 0
  fi
  echo "geolock: ERROR $what download failed and there is no cached list" >&2
  return 1
}

failed=0
for fam in "${fams[@]}"; do
  for cc in "${codes[@]}"; do
    fetch_cc "$cc" "$fam" || failed=1
  done
done
# Never load a partial list: in allow mode it would cut off whole countries.
[[ $failed -eq 0 ]] || die "not applying; fix the downloads above and re-run"

# Re-check every cached list before use: caches written by older, laxer
# versions (or damaged on disk) must never reach nft.
lists="$(mktemp -d "$CACHE/.lists.XXXXXX")"
trap 'rm -rf "$lists"' EXIT
for fam in "${fams[@]}"; do
  for cc in "${codes[@]}"; do
    what="${cc^^}"
    [[ "$fam" == "v6" ]] && what="${cc^^} IPv6"
    if [[ "$fam" == "v6" && -f "$CACHE/$cc.v6" && ! -s "$CACHE/$cc.v6" ]]; then
      : > "$lists/$cc.v6"   # no IPv6 allocations upstream
      continue
    fi
    cidr_filter "$fam" < "$CACHE/$cc.$fam" > "$lists/$cc.$fam" \
      || die "cached $what list failed validation; nothing changed (try --refresh)"
  done
done
if [[ "$GEOLOCK_IPV6" == "1" ]] && ! grep -qs . "$lists"/*.v6; then
  die "no IPv6 prefixes for any selected country; set GEOLOCK_IPV6=0"
fi
app_cg="${GEOLOCK_APP_CGROUP:-}"
app_cg="${app_cg#"${app_cg%%[!/]*}"}"
if [[ "$GEOLOCK_MODE" == "allow" && -n "$app_cg" ]] \
  && [[ ! "$app_cg" =~ ^[A-Za-z0-9@._:-]+(/[A-Za-z0-9@._:-]+)*$ ]]; then
  die "GEOLOCK_APP_CGROUP must be a cgroup path like user.slice/app.slice"
fi
# nft resolves a cgroupv2 path when the ruleset is loaded and refuses the
# whole ruleset if that cgroup does not exist (yet), e.g. at boot before
# tailscaled or the user's session has started. A missing cgroup has no
# sockets, so its rules would match nothing: leave them out instead of
# failing the geolock. GEOLOCK_CGROUP_ROOT is for tests.
cg_root="${GEOLOCK_CGROUP_ROOT:-/sys/fs/cgroup}"
underlay="${GEOLOCK_TAILSCALE_UNDERLAY:-0}"
if [[ "$GEOLOCK_OUTBOUND" == "1" && "$underlay" == "1" && ! -d "$cg_root/system.slice/tailscaled.service" ]]; then
  echo "geolock: WARNING cgroup system.slice/tailscaled.service does not exist; leaving out the tailscale underlay rule" >&2
  underlay=0
fi
if [[ "$GEOLOCK_OUTBOUND" == "1" && "$GEOLOCK_MODE" == "allow" && -n "$app_cg" && ! -d "$cg_root/$app_cg" ]]; then
  echo "geolock: WARNING cgroup $app_cg does not exist; leaving out its rules (re-run the geolock once it exists)" >&2
  app_cg=""
fi

v6=0
[[ "$GEOLOCK_IPV6" == "1" ]] && v6=1
# Rules are emitted as: deny mode matches the listed set, allow mode
# everything outside it. $1 = selector (e.g. "ip saddr"), $2 = set.
match() { if [[ "$GEOLOCK_MODE" == "deny" ]]; then echo "$1 @$2"; else echo "$1 != @$2"; fi; }

tmp_nft="$(mktemp "$CACHE/.geolock.XXXXXX.nft")"
trap 'rm -rf "$tmp_nft" "$lists"' EXIT
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
    sed 's/^/      /; s/$/,/' "$lists/$cc.v4"
  done
  echo '    }'
  echo '  }'
  if (( v6 )); then
    # Loopback, link-local, ULA (includes Tailscale fd7a:115c:a1e0::/48).
    echo '  set pass6 {'
    echo '    type ipv6_addr'
    echo '    flags interval'
    echo '    auto-merge'
    echo '    elements = { ::1/128, fe80::/10, fc00::/7 }'
    echo '  }'
    echo '  set listed6 {'
    echo '    type ipv6_addr'
    echo '    flags interval'
    echo '    auto-merge'
    echo '    elements = {'
    for cc in "${codes[@]}"; do
      sed 's/^/      /; s/$/,/' "$lists/$cc.v6"
    done
    echo '    }'
    echo '  }'
  fi
  if [[ "$GEOLOCK_INBOUND" == "1" ]]; then
    echo '  chain input {'
    echo '    type filter hook input priority filter - 5; policy accept;'
    echo '    ip saddr @pass4 accept'
    echo "    meta l4proto { tcp, udp } th dport { $ports } $(match "ip saddr" listed4) counter drop"
    if (( v6 )); then
      echo '    ip6 saddr @pass6 accept'
      echo "    meta l4proto { tcp, udp } th dport { $ports } $(match "ip6 saddr" listed6) counter drop"
    fi
    echo '  }'
    # Docker-published ports are DNATed in prerouting and then routed to the
    # container, so they cross forward, not input. Match on the original
    # (host) port so this covers Pi-hole :53 and DoT :853 in containers.
    echo '  chain forward {'
    echo '    type filter hook forward priority filter - 5; policy accept;'
    echo '    ip saddr @pass4 accept'
    echo "    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { $ports } $(match "ip saddr" listed4) counter drop"
    if (( v6 )); then
      echo '    ip6 saddr @pass6 accept'
      echo "    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { $ports } $(match "ip6 saddr" listed6) counter drop"
    fi
    echo '  }'
  fi
  if [[ "$GEOLOCK_OUTBOUND" == "1" ]]; then
    echo '  chain output {'
    echo '    type filter hook output priority filter - 5; policy accept;'
    echo '    ip daddr @pass4 accept'
    (( v6 )) && echo '    ip6 daddr @pass6 accept'
    # Optional host extras (env, off by default; the cgroups must exist):
    #   GEOLOCK_TAILSCALE_UNDERLAY=1  let tailscaled reach any country
    #   GEOLOCK_APP_CGROUP=<path>     allow mode: that cgroup may only reach
    #                                 listed countries (no IPv6 unless
    #                                 GEOLOCK_IPV6=1)
    if [[ "$underlay" == "1" ]]; then
      echo '    socket cgroupv2 level 2 "system.slice/tailscaled.service" accept comment "tailscale underlay"'
    fi
    if [[ "$GEOLOCK_MODE" == "allow" && -n "$app_cg" ]]; then
      IFS=/ read -ra _parts <<<"$app_cg"
      app_lvl="${#_parts[@]}"
      if (( v6 )); then
        echo "    socket cgroupv2 level ${app_lvl} \"${app_cg}\" ip6 daddr != @listed6 drop"
      else
        echo "    meta nfproto ipv6 socket cgroupv2 level ${app_lvl} \"${app_cg}\" drop"
      fi
      echo "    socket cgroupv2 level ${app_lvl} \"${app_cg}\" ip daddr != @listed4 drop"
    fi
    echo "    meta l4proto { tcp, udp } th dport { $ports } $(match "ip daddr" listed4) counter drop"
    [[ "$GEOLOCK_MODE" == "deny" ]] \
      && echo "    meta l4proto { tcp, udp } th sport { $ports } ip daddr @listed4 counter drop"
    if (( v6 )); then
      echo "    meta l4proto { tcp, udp } th dport { $ports } $(match "ip6 daddr" listed6) counter drop"
      [[ "$GEOLOCK_MODE" == "deny" ]] \
        && echo "    meta l4proto { tcp, udp } th sport { $ports } ip6 daddr @listed6 counter drop"
    fi
    echo '  }'
  fi
  echo '}'
} > "$tmp_nft"

nft_check "$tmp_nft" || die "generated ruleset failed nft -c; nothing changed"
chmod 644 "$tmp_nft"
codes_up="${codes[*]^^}"
if [[ "$DRY_RUN" == "1" ]]; then
  mv -f "$tmp_nft" "$NFT_OUT"
  rm -rf "$lists"
  trap - EXIT
  echo "geolock dry run OK: $NFT_OUT mode=$GEOLOCK_MODE codes=$codes_up"
  exit 0
fi

# --- load, verify, roll back -------------------------------------------------
# PREV is a reloadable snapshot of the table that is live right now (taken
# with nft list, so it is exactly what the kernel has, counters included).
PREV="$CACHE/geolock.prev.nft"
had_table=0
snap="$(mktemp "$CACHE/.geolock.prev.XXXXXX")"
trap 'rm -rf "$tmp_nft" "$lists" "$snap"' EXIT
if "$NFT" list table inet geolock > "$snap.body" 2>/dev/null; then
  had_table=1
  { echo '#!/usr/bin/nft -f'; echo 'table inet geolock'; echo 'delete table inet geolock'
    cat "$snap.body"; } > "$snap"
  rm -f "$snap.body"
  "$NFT" -c -f "$snap" || die "cannot snapshot the live geolock table for rollback; nothing changed"
  chmod 600 "$snap"
  mv -f "$snap" "$PREV"
else
  rm -f "$snap.body" "$snap"
fi

# verify_loaded FILE: every chain in FILE is live with the same number of
# drop rules, and the first prefix of each listed set is a member.
verify_loaded() {
  local f="$1" c want got first
  for c in input forward output; do
    want="$(awk -v c="$c" '$0 ~ "^  chain "c" [{]$" {on=1; next} on && /^  }$/ {on=0} on && / drop$/ {n++} END {print n+0}' "$f")"
    if grep -q "^  chain $c {\$" "$f"; then
      got="$("$NFT" list chain inet geolock "$c" 2>/dev/null | grep -c ' drop$')" || return 1
      [[ "$got" == "$want" ]] || { echo "geolock: verify: chain $c has $got drop rules, expected $want" >&2; return 1; }
    fi
  done
  for c in listed4 listed6; do
    first="$(awk -v s="$c" '$0 == "  set "s" {" {on=1; next} on && /^      / {sub(/^ +/, ""); sub(/\/.*/, ""); print; exit}' "$f")"
    [[ -z "$first" ]] && continue
    "$NFT" get element inet geolock "$c" "{ $first }" > /dev/null 2>&1 \
      || { echo "geolock: verify: $first missing from set $c" >&2; return 1; }
  done
}

had_out=0
[[ -s "$NFT_OUT" ]] && cp -p "$NFT_OUT" "$NFT_OUT.bak" && had_out=1
mv -f "$tmp_nft" "$NFT_OUT"
rm -rf "$lists"
trap - EXIT
if "$NFT" -f "$NFT_OUT" && verify_loaded "$NFT_OUT"; then
  rm -f "$NFT_OUT.bak"
  echo "geolock applied mode=$GEOLOCK_MODE codes=$codes_up"
  echo "drop counters: nft list table inet geolock | grep counter"
  exit 0
fi
mv -f "$NFT_OUT" "$CACHE/geolock.failed.nft"
(( had_out )) && mv -f "$NFT_OUT.bak" "$NFT_OUT"
if (( had_table )); then
  if "$NFT" -f "$PREV"; then
    die "new ruleset failed to load or verify; rolled back to the previous table (see $CACHE/geolock.failed.nft)"
  fi
  die "new ruleset failed AND rollback from $PREV failed; check: nft list table inet geolock"
fi
die "new ruleset failed to load or verify and there was no previous table (see $CACHE/geolock.failed.nft)"
