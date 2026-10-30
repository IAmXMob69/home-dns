#!/usr/bin/env bash
# Exercise scripts/install-geolock-system.sh against a fake root (INSTALL_SYSROOT):
# identity gate, install, reinstall, refusal when the render differs, failure
# mid-install (automatic rollback) and --rollback. Touches nothing outside a
# temp dir. Needs go/bin/geolock-apply built and nft (root, or unshare -rn).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INST="$REPO/scripts/install-geolock-system.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
assert() { local m="$1"; shift; if "$@"; then ok "$m"; else bad "$m"; fi; }

UNIT=etc/systemd/system/vaultos-country-block.service
LIVE="$T/live"
S="$T/root"
mkdir -p "$LIVE/scripts" "$LIVE/lib" "$LIVE/geolock/cache" "$T/mirror/zz" "$S/etc/systemd/system"
cp "$REPO/scripts/geolock-apply.sh" "$LIVE/scripts/"
cp "$REPO/lib/cidr.sh" "$LIVE/lib/"
printf '198.51.100.0/24\n203.0.113.0/25\n' > "$T/mirror/zz/ipv4-aggregated.txt"
printf 'GEOLOCK_ENABLED=1\nGEOLOCK_MODE=allow\nGEOLOCK_ALLOW_COUNTRIES=ZZ\nGEOLOCK_PORTS=53,853\n' \
  > "$LIVE/geolock/settings.env"
# The "live" ruleset, as the old unit would have written it.
PIHOLE_NO_GO=1 GEOLOCK_DRY_RUN=1 GEOLOCK_URL_BASE="file://$T/mirror" \
  bash "$LIVE/scripts/geolock-apply.sh" > /dev/null
cat > "$S/$UNIT" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
ExecStartPost=-$LIVE/scripts/geolock-apply.sh
EOF
cp "$S/$UNIT" "$T/unit.orig"
inst() { INSTALL_SYSROOT="$S" "$INST" "$@" > "$T/out" 2>&1; }
managed_absent() {
  [[ ! -e "$S/usr/local/lib/home-dns" && ! -e "$S/etc/home-dns" && ! -e "$S/var/lib/home-dns/geolock" \
    && ! -e "$S/etc/systemd/system/vaultos-country-block.service.d/10-home-dns-geolock.conf" ]]
}
dropin_ok() {
  grep -qx 'ExecStartPost=' "$1" && grep -qx 'ExecStartPost=/usr/local/lib/home-dns/geolock' "$1"
}

echo "== dry run"
assert "dry run succeeds" inst --dry-run
assert "dry run passes the identity gate (go and bash)" \
  bash -c "grep -q 'identity check (go): byte-identical' '$T/out' && grep -q 'identity check (bash): byte-identical' '$T/out'"
assert "dry run changes nothing" managed_absent

echo "== refuses when the render would differ"
cp "$LIVE/geolock/settings.env" "$T/settings.keep"
echo "GEOLOCK_PORTS=53" >> "$LIVE/geolock/settings.env"
assert "install refused" bash -c "! INSTALL_SYSROOT='$S' '$INST' > '$T/out' 2>&1"
assert "reason: render differs" grep -q 'differs from the live' "$T/out"
assert "nothing installed, no backup" bash -c "[[ ! -d '$S/var/backups' ]]"
cp "$T/settings.keep" "$LIVE/geolock/settings.env"

echo "== install"
assert "install succeeds" inst
d="$S/etc/systemd/system/vaultos-country-block.service.d/10-home-dns-geolock.conf"
assert "drop-in clears and replaces ExecStartPost (no '-')" dropin_ok "$d"
assert "unit file itself untouched" cmp -s "$S/$UNIT" "$T/unit.orig"
assert "binaries installed 0755" bash -c "[[ \$(stat -c %a '$S/usr/local/lib/home-dns/go/bin/geolock-apply') == 755 \
  && \$(stat -c %a '$S/usr/local/lib/home-dns/geolock') == 755 ]]"
assert "settings copied unchanged" cmp -s "$LIVE/geolock/settings.env" "$S/etc/home-dns/geolock.env"
assert "cache seeded with the live ruleset" cmp -s "$LIVE/geolock/cache/geolock.nft" "$S/var/lib/home-dns/geolock/geolock.nft"
first="$(ls -d "$S"/var/backups/home-dns-geolock-*)"
assert "backup manifest records the old ExecStartPost" \
  grep -qx "execstartpost -$LIVE/scripts/geolock-apply.sh" "$first/manifest"

echo "== installed wrapper renders the same ruleset"
sed -e "s#=/etc/home-dns/#=$S/etc/home-dns/#" -e "s#=/var/lib/home-dns/#=$T/wcache/#" \
  "$S/etc/home-dns/geolock.service.env" > "$T/w.env"
mkdir -p "$T/wcache"
cp -a "$S/var/lib/home-dns/geolock" "$T/wcache/geolock"
assert "wrapper dry run" env HOME_DNS_GEOLOCK_ENV="$T/w.env" GEOLOCK_DRY_RUN=1 GEOLOCK_URL_BASE=file:///nonexistent \
  "$S/usr/local/lib/home-dns/geolock"
assert "wrapper output byte-identical" cmp -s "$T/wcache/geolock/geolock.nft" "$LIVE/geolock/cache/geolock.nft"

echo "== reinstall"
sleep 1
assert "reinstall succeeds" inst
assert "reinstall gates against the installed copy" grep -q 'already installed' "$T/out"
assert "drop-in still correct" dropin_ok "$d"

echo "== failure mid-install rolls back by itself"
sleep 1
# A file where a directory must go: install fails even as root.
rm -rf "$S/usr/local/lib/home-dns/lib"
touch "$S/usr/local/lib/home-dns/lib"
assert "failing install exits non-zero" bash -c "! INSTALL_SYSROOT='$S' '$INST' > '$T/out' 2>&1"
assert "it rolled back" grep -q 'install failed; rolling back' "$T/out"
assert "previous install restored" dropin_ok "$d"
assert "tree restored exactly as it was before that run" test -f "$S/usr/local/lib/home-dns/lib"
assert "binary from the previous install kept" cmp -s "$REPO/go/bin/geolock-apply" "$S/usr/local/lib/home-dns/go/bin/geolock-apply"
assert "previous settings restored" cmp -s "$LIVE/geolock/settings.env" "$S/etc/home-dns/geolock.env"

echo "== --rollback to before the first install"
assert "rollback succeeds" inst --rollback "$first"
assert "managed paths removed" managed_absent
assert "ExecStartPost back to the original" grep -q "rollback done; ExecStartPost=-$LIVE/scripts/geolock-apply.sh" "$T/out"
assert "unit file identical to the original" cmp -s "$S/$UNIT" "$T/unit.orig"

echo "install-geolock-system: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
