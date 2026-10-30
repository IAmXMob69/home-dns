#!/usr/bin/env bash
# Dry-run checks for scripts/geolock-apply.sh and its Go build (no firewall
# change, no network): every case must render the same file from both.
#   1. Boot-time cgroups: a configured cgroup that does not exist yet must not
#      fail the geolock; its rules are left out. Present cgroups are kept.
#   2. IPv6 "no list upstream" records (empty cache files) are a valid cache
#      when the download fails, e.g. at boot before the network is up.
# Needs nft. As non-root it runs nft -c in `unshare -rn`; where unprivileged
# user namespaces are disabled (CI), run it with sudo.
#   tests/geolock-apply-test.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=1; }

(cd "$ROOT/go" && go build -o "$work/geolock-apply" ./cmd/geolock-apply)

mkcache() {
  rm -rf "$work/cache"; mkdir -p "$work/cache"
  printf '198.51.100.0/24\n' > "$work/cache/zz.v4"
  printf '203.0.113.0/24\n' > "$work/cache/yy.v4"
  printf '2001:db8:2::/48\n' > "$work/cache/yy.v6"
  : > "$work/cache/zz.v6"   # zz has no IPv6 list upstream
}

# render NAME SETTINGS... : dry run with Bash and Go; leave $work/NAME.{bash,go}.{nft,log}
render() {
  local name="$1" impl rc; shift
  printf '%s\n' GEOLOCK_ENABLED=1 GEOLOCK_MODE=allow GEOLOCK_ALLOW_COUNTRIES=ZZ,YY "$@" > "$work/settings.env"
  for impl in bash go; do
    mkcache
    rc=0
    if [[ "$impl" == bash ]]; then
      env GEOLOCK_SETTINGS="$work/settings.env" GEOLOCK_CACHE="$work/cache" GEOLOCK_DRY_RUN=1 \
        GEOLOCK_URL_BASE=http://127.0.0.1:9 PIHOLE_NO_GO=1 "${ENVX[@]}" \
        bash "$ROOT/scripts/geolock-apply.sh" > "$work/$name.$impl.log" 2>&1 || rc=$?
    else
      env GEOLOCK_SETTINGS="$work/settings.env" GEOLOCK_CACHE="$work/cache" GEOLOCK_DRY_RUN=1 \
        GEOLOCK_URL_BASE=http://127.0.0.1:9 PIHOLE_ROOT="$ROOT" "${ENVX[@]}" \
        "$work/geolock-apply" > "$work/$name.$impl.log" 2>&1 || rc=$?
    fi
    if [[ $rc -ne 0 ]]; then
      bad "$name ($impl) exited $rc:"; sed 's/^/         /' "$work/$name.$impl.log"
      : > "$work/$name.$impl.nft"; continue
    fi
    cp "$work/cache/geolock.nft" "$work/$name.$impl.nft"
  done
  if cmp -s "$work/$name.bash.nft" "$work/$name.go.nft"; then ok "$name: Bash and Go render the same file"
  else bad "$name: Bash and Go differ"; diff "$work/$name.bash.nft" "$work/$name.go.nft" | head -10; fi
}
has() { if grep -qF -- "$2" "$work/$1.go.nft"; then ok "$1: has $2"; else bad "$1: missing $2"; fi; }
hasnt() { if grep -qF -- "$2" "$work/$1.go.nft"; then bad "$1: unexpected $2"; else ok "$1: no $2"; fi; }
warned() {
  local impl
  for impl in bash go; do
    if grep -qF -- "$2" "$work/$1.$impl.log"; then ok "$1 ($impl): warns $2"; else bad "$1 ($impl): no warning $2"; fi
  done
}

app=user.slice/app.slice
cg="$work/cgroup"   # empty: nothing exists in it
mkdir -p "$cg"
echo "== cgroups missing (boot before tailscaled / the session)"
ENVX=(GEOLOCK_CGROUP_ROOT="$cg" GEOLOCK_TAILSCALE_UNDERLAY=1 GEOLOCK_APP_CGROUP="$app")
render missing
hasnt missing cgroupv2
has missing 'ip saddr != @listed4 counter drop'
warned missing 'system.slice/tailscaled.service does not exist'
warned missing "$app does not exist"

echo "== cgroups present (real cgroups: nft -c resolves them on this host)"
# system.slice exists on every systemd host; tailscaled only where it runs.
ENVX=(GEOLOCK_TAILSCALE_UNDERLAY=1 GEOLOCK_APP_CGROUP=system.slice)
render present
has present 'socket cgroupv2 level 1 "system.slice" ip daddr != @listed4 drop'
if [[ -d /sys/fs/cgroup/system.slice/tailscaled.service ]]; then
  has present 'socket cgroupv2 level 2 "system.slice/tailscaled.service" accept comment "tailscale underlay"'
else
  hasnt present tailscaled.service
fi

echo "== IPv6 on, offline, one country with no IPv6 list upstream"
ENVX=(GEOLOCK_CGROUP_ROOT="$cg")
render v6offline GEOLOCK_IPV6=1 GEOLOCK_MAX_AGE_DAYS=7
has v6offline '2001:db8:2::/48,'
printf '%s\n' GEOLOCK_ENABLED=1 GEOLOCK_MODE=allow GEOLOCK_ALLOW_COUNTRIES=ZZ,YY GEOLOCK_IPV6=1 > "$work/settings.env"
for impl in bash go; do
  mkcache; touch -d '30 days ago' "$work/cache/zz.v6"
  if [[ "$impl" == bash ]]; then set -- bash "$ROOT/scripts/geolock-apply.sh"; else set -- "$work/geolock-apply"; fi
  if env GEOLOCK_SETTINGS="$work/settings.env" GEOLOCK_CACHE="$work/cache" GEOLOCK_DRY_RUN=1 \
      GEOLOCK_URL_BASE=http://127.0.0.1:9 PIHOLE_NO_GO=1 PIHOLE_ROOT="$ROOT" "$@" > "$work/stale.log" 2>&1 \
      && [[ -f "$work/cache/zz.v6" && ! -s "$work/cache/zz.v6" ]]; then
    ok "v6stale ($impl): stale no-list record kept when the download fails"
  else
    bad "v6stale ($impl):"; sed 's/^/         /' "$work/stale.log"
  fi
done

if [[ $fail -ne 0 ]]; then echo "geolock-apply-test: FAILED"; exit 1; fi
echo "geolock-apply-test: all passed"
