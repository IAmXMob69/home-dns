#!/bin/bash
# Apply the India inbound block. Idempotent. Run as root: sudo (or pkexec) <this script>
# Installs the rule to /etc/nftables.d and a boot unit, checks that no other
# nftables table changed, and rolls itself back if any step fails.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo or pkexec)" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
NFT=/etc/nftables.d/india-inbound-block.nft
UNIT=/etc/systemd/system/vaultos-india-inbound.service
BK=/var/backups/india-inbound-$(date +%Y%m%d-%H%M%S); mkdir -p "$BK"
# snapshot the tables we must not change
for t in india_block india_ca_block africa_block israel_block saudi_block malice_block dns_egress geolock; do
  nft list table inet $t > "$BK/$t.before" 2>/dev/null || true; done
nft list tables > "$BK/tables.before"
nft list table inet india_inbound > "$BK/india_inbound.before" 2>/dev/null || true
[ -f "$NFT" ] && cp -a "$NFT" "$BK/"; [ -f "$UNIT" ] && cp -a "$UNIT" "$BK/"
nft -c -f "$SRC/india-inbound-block.nft"
rollback() {
  echo "FAILED - rolling back" >&2
  nft delete table inet india_inbound 2>/dev/null || true
  [ -s "$BK/india_inbound.before" ] && { echo 'destroy table inet india_inbound'; cat "$BK/india_inbound.before"; } | nft -f - || true
  if [ -f "$BK/india-inbound-block.nft" ]; then cp -a "$BK/india-inbound-block.nft" "$NFT"; else rm -f "$NFT"; fi
  if [ -f "$BK/vaultos-india-inbound.service" ]; then cp -a "$BK/vaultos-india-inbound.service" "$UNIT"; else systemctl disable vaultos-india-inbound.service 2>/dev/null || true; rm -f "$UNIT"; fi
  systemctl daemon-reload; exit 1
}
trap rollback ERR
install -o root -g root -m 0644 "$SRC/india-inbound-block.nft" "$NFT"
install -o root -g root -m 0644 "$SRC/vaultos-india-inbound.service" "$UNIT"
systemctl daemon-reload
systemctl enable vaultos-india-inbound.service
systemctl restart vaultos-india-inbound.service
nft list table inet india_inbound >/dev/null
for t in india_block india_ca_block africa_block israel_block saudi_block malice_block dns_egress geolock; do
  [ -s "$BK/$t.before" ] || continue
  nft list table inet $t | grep -v 'counter packets' > "$BK/$t.after"
  grep -v 'counter packets' "$BK/$t.before" | diff -q - "$BK/$t.after" >/dev/null || { echo "table $t changed" >&2; false; }
done
# sanity: local DNS must still answer
getent hosts archlinux.org >/dev/null || dig +time=3 +tries=2 @127.0.0.1 archlinux.org >/dev/null
trap - ERR
echo "India inbound block active. Backup: $BK"
echo "Undo: sudo systemctl disable --now vaultos-india-inbound.service"
