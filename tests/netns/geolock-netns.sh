#!/usr/bin/env bash
# End-to-end geolock test inside throwaway network namespaces. Loads the real
# ruleset with scripts/geolock-apply.sh and sends DNS queries over a veth pair
# from listed and unlisted source prefixes (IPv4 and IPv6, inbound and
# outbound), then checks load/verify/rollback.
#
# Needs no root on the host. Run it inside a fresh user+net namespace:
#   unshare -rn tests/netns/geolock-netns.sh
# or, where unprivileged user namespaces are disabled (e.g. CI):
#   sudo unshare -n tests/netns/geolock-netns.sh
# It refuses to run anywhere except a fresh network namespace, so it can
# never touch the host firewall.
#
# GEOLOCK_GO_BIN=/path/to/geolock-apply also runs every case with the Go build.
#
# Addresses are documentation prefixes only:
#   listed  ("zz"): 198.51.100.0/24, 2001:db8:1::/48
#   unlisted ("yy"): 203.0.113.0/24, 2001:db8:2::/48
#   link: 192.0.2.0/24, 2001:db8:ff::/64; server = .1/::1, client = .2/::2
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROBE=(python3 "$HERE/dnsprobe.py")

die() { echo "netns: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "run inside a namespace: unshare -rn $0"
links="$(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"
[[ "$links" == "lo " ]] || die "refusing: this is not a fresh network namespace (links: $links)"

work="$(mktemp -d)"
pids=()
cleanup() {
  local p
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

ip link set lo up
# Client namespace: a child netns of this one, held open by a sleeper.
unshare -n sleep infinity &
cpid=$!
pids+=("$cpid")
sleep 0.2
C() { nsenter -t "$cpid" -n "$@"; }
ip link add veth-s type veth peer name veth-c netns "$cpid"
ip addr add 192.0.2.1/24 dev veth-s
ip -6 addr add 2001:db8:ff::1/64 dev veth-s nodad
ip link set veth-s up
ip route add 198.51.100.0/24 via 192.0.2.2
ip route add 203.0.113.0/24 via 192.0.2.2
ip -6 route add 2001:db8:1::/48 via 2001:db8:ff::2
ip -6 route add 2001:db8:2::/48 via 2001:db8:ff::2
C ip link set lo up
C ip addr add 192.0.2.2/24 dev veth-c
C ip -6 addr add 2001:db8:ff::2/64 dev veth-c nodad
for a in 198.51.100.10/32 203.0.113.10/32; do C ip addr add "$a" dev veth-c; done
for a in 2001:db8:1::10/128 2001:db8:2::10/128; do C ip -6 addr add "$a" dev veth-c nodad; done
C ip link set veth-c up
C ip -6 route add default via 2001:db8:ff::1
C ip route add default via 192.0.2.1

# A responder on each side: the server namespace (where the geolock is
# loaded) answers inbound queries; the client answers outbound ones.
"${PROBE[@]}" serve & pids+=("$!")
nsenter -t "$cpid" -n "${PROBE[@]}" serve & pids+=("$!")
sleep 0.5

# Mirror: ipverse layout with file:// URLs.
mkdir -p "$work/mirror/zz" "$work/mirror/yy"
printf '# Country: test\n#\n198.51.100.0/24\n' > "$work/mirror/zz/ipv4-aggregated.txt"
printf '# Country: test\n#\n2001:db8:1::/48\n' > "$work/mirror/zz/ipv6-aggregated.txt"
printf '# Country: test\n#\n203.0.113.0/24\n' > "$work/mirror/yy/ipv4-aggregated.txt"
printf '# Country: test\n#\n2001:db8:2::/48\n' > "$work/mirror/yy/ipv6-aggregated.txt"

pass=0 fail=0
ok()  { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
# assert DESCRIPTION -- command: ok when the command succeeds.
assert() {
  local what="$1"; shift 2
  if "$@"; then ok "$what"; else bad "$what"; fi
}
refuses() { ! "$@" > /dev/null 2>&1; }
no_table() { ! nft list table inet geolock > /dev/null 2>&1; }
# The live table without counter values, for before/after comparisons.
table() { nft list table inet geolock | sed 's/counter packets [0-9]* bytes [0-9]*/counter/'; }
# expect answered|blocked DESCRIPTION -- command
expect() {
  local want="$1" what="$2"; shift 3
  local got=blocked
  "$@" && got=answered
  if [[ "$got" == "$want" ]]; then ok "$what: $got"; else bad "$what: $got (want $want)"; fi
}
in4()  { C "${PROBE[@]}" query "$1" 192.0.2.1 "${@:2}"; }
in6()  { C "${PROBE[@]}" query "$1" 2001:db8:ff::1 "${@:2}"; }
out4() { "${PROBE[@]}" query 192.0.2.1 "$1"; }
out6() { "${PROBE[@]}" query 2001:db8:ff::1 "$1"; }

# check IN4 IN6 OUT4 OUT6: expected result for the unlisted source/target
# (listed ones must always be answered).
check() {
  expect answered "in  v4 listed  " -- in4 198.51.100.10
  expect "$1"     "in  v4 unlisted" -- in4 203.0.113.10
  expect "$1"     "in  v4 unlisted tcp" -- in4 203.0.113.10 --tcp
  expect answered "in  v6 listed  " -- in6 2001:db8:1::10
  expect "$2"     "in  v6 unlisted" -- in6 2001:db8:2::10
  expect answered "out v4 listed  " -- out4 198.51.100.10
  expect "$3"     "out v4 unlisted" -- out4 203.0.113.10
  expect answered "out v6 listed  " -- out6 2001:db8:1::10
  expect "$4"     "out v6 unlisted" -- out6 2001:db8:2::10
}

# dropped CHAIN RULE_SUFFIX: packets > 0 for that geolock rule in $work/nft.prom.
dropped() {
  awk -v c="chain=\"$1\"" -v r="$2\"}" '
    /^home_dns_nft_drop_packets_total/ && index($0, c) && index($0, r) && $NF > 0 { hit = 1 }
    END { exit !hit }' "$work/nft.prom"
}

impls=(bash)
[[ -n "${GEOLOCK_GO_BIN:-}" ]] && impls+=(go)

# run_apply IMPL [ARGS]: one geolock-apply run with $work/settings.env.
run_apply() {
  local impl="$1"; shift
  if [[ "$impl" == "go" ]]; then
    GEOLOCK_SETTINGS="$work/settings.env" GEOLOCK_CACHE="$work/cache" \
      GEOLOCK_URL_BASE="file://$work/mirror" PIHOLE_ROOT="$ROOT" "$GEOLOCK_GO_BIN" "$@"
  else
    GEOLOCK_SETTINGS="$work/settings.env" GEOLOCK_CACHE="$work/cache" \
      GEOLOCK_URL_BASE="file://$work/mirror" PIHOLE_NO_GO=1 bash "$ROOT/scripts/geolock-apply.sh" "$@"
  fi
}
# apply IMPL SETTINGS...: write settings (enabled) and apply with --refresh.
apply() {
  local impl="$1"; shift
  printf '%s\n' "GEOLOCK_ENABLED=1" "$@" > "$work/settings.env"
  run_apply "$impl" --refresh
}
# fails_with_rollback NFT_WRAPPER CMD...: CMD (with GEOLOCK_NFT=wrapper)
# must fail and say it rolled back.
fails_with_rollback() {
  local out wrapper="$1"; shift
  if out="$(GEOLOCK_NFT="$wrapper" "$@" 2>&1)"; then echo "    unexpected success" >&2; return 1; fi
  grep -q 'rolled back to the previous table' <<<"$out" || { echo "    $out" >&2; return 1; }
}
allow=(GEOLOCK_MODE=allow GEOLOCK_ALLOW_COUNTRIES=ZZ)

# Fake nft wrappers for the rollback cases.
cat > "$work/nft-fail-load" <<'W'
#!/usr/bin/env bash
if [[ "${1:-}" == "-f" && "${2:-}" == */geolock.nft ]]; then echo "injected load failure" >&2; exit 1; fi
exec nft "$@"
W
cat > "$work/nft-fail-verify" <<'W'
#!/usr/bin/env bash
if [[ "${1:-}" == "get" ]]; then exit 1; fi
exec nft "$@"
W
chmod +x "$work/nft-fail-load" "$work/nft-fail-verify"

# Wait for links, neighbour discovery and both responders to settle.
for _ in $(seq 40); do
  in4 198.51.100.10 && in6 2001:db8:1::10 && out4 198.51.100.10 && out6 2001:db8:1::10 && break
  sleep 0.25
done

echo "== baseline, no geolock"
check answered answered answered answered

for impl in "${impls[@]}"; do
  rm -rf "$work/cache"
  echo "== [$impl] allow, IPv4 only (today's live scope: IPv6 is not geolocked)"
  apply "$impl" "${allow[@]}" > /dev/null
  check blocked answered blocked answered

  echo "== [$impl] allow, GEOLOCK_IPV6=1"
  apply "$impl" "${allow[@]}" GEOLOCK_IPV6=1 > /dev/null
  check blocked blocked blocked blocked
  # The drops above must show up in monitoring/nft-counters.py output.
  python3 "$ROOT/monitoring/nft-counters.py" --tables geolock > "$work/nft.prom"
  for r in input:ip_saddr_not_listed4 input:ip6_saddr_not_listed6 \
      output:ip_daddr_not_listed4 output:ip6_daddr_not_listed6; do
    assert "counter export: $r > 0" -- dropped "${r%%:*}" "${r#*:}"
  done

  echo "== [$impl] allow, IPv6, GEOLOCK_INBOUND=0 (outbound only)"
  apply "$impl" "${allow[@]}" GEOLOCK_IPV6=1 GEOLOCK_INBOUND=0 > /dev/null
  check answered answered blocked blocked

  echo "== [$impl] allow, IPv6, GEOLOCK_OUTBOUND=0 (inbound only)"
  apply "$impl" "${allow[@]}" GEOLOCK_IPV6=1 GEOLOCK_OUTBOUND=0 > /dev/null
  check blocked blocked answered answered

  echo "== [$impl] deny YY, IPv6"
  apply "$impl" GEOLOCK_MODE=deny GEOLOCK_DENY_COUNTRIES=YY GEOLOCK_IPV6=1 > /dev/null
  check blocked blocked blocked blocked

  echo "== [$impl] rollback: new file fails to load"
  apply "$impl" "${allow[@]}" GEOLOCK_IPV6=1 > /dev/null
  before="$(table)"
  good="$(sha256sum < "$work/cache/geolock.nft")"
  assert "apply fails and reports rollback" -- fails_with_rollback "$work/nft-fail-load" apply "$impl" "${allow[@]}"
  assert "live table unchanged" -- test "$(table)" == "$before"
  assert "geolock.nft restored" -- test "$(sha256sum < "$work/cache/geolock.nft")" == "$good"
  assert "failed file kept" -- test -s "$work/cache/geolock.failed.nft"
  check blocked blocked blocked blocked

  echo "== [$impl] rollback: new file loads but fails verification"
  assert "apply fails and reports rollback" -- fails_with_rollback "$work/nft-fail-verify" apply "$impl" "${allow[@]}"
  assert "IPv6 table restored (not the IPv4-only one that was loaded)" -- test "$(table)" == "$before"
  check blocked blocked blocked blocked

  echo "== [$impl] bad cache is refused, nothing changes"
  printf '3.0.0.1/8\n' > "$work/cache/zz.v4"
  touch "$work/cache/zz.v4"
  assert "lax cache refused" -- refuses run_apply "$impl"
  assert "live table unchanged" -- test "$(table)" == "$before"

  echo "== [$impl] disable removes the table"
  printf 'GEOLOCK_ENABLED=0\n' > "$work/settings.env"
  run_apply "$impl" > /dev/null
  assert "table removed" -- no_table
  check answered answered answered answered
done

echo "netns: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
