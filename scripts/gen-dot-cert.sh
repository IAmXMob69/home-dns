#!/usr/bin/env bash
# Generate a local DNS-over-TLS cert for Unbound (LAN Private DNS clients).
# The key is 0600. Unbound runs as 101:102 in its container, so install.sh
# hands the key to that uid (see fix_key_owner there).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/unbound"
CN="${1:-pihole.lan}"
mkdir -p "$DIR"
umask 077
tmp_key="$(mktemp "$DIR/.tls.key.XXXXXX")"
tmp_pem="$(mktemp "$DIR/.tls.pem.XXXXXX")"
trap 'rm -f "$tmp_key" "$tmp_pem"' EXIT
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout "$tmp_key" \
  -out "$tmp_pem" \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:${CN},DNS:pi.hole"
chmod 600 "$tmp_key"
chmod 644 "$tmp_pem"
# mv replaces the files even if the old key is owned by the Unbound uid.
mv -f "$tmp_key" "$DIR/tls.key"
mv -f "$tmp_pem" "$DIR/tls.pem"
trap - EXIT
echo "Wrote unbound/tls.key (0600) and unbound/tls.pem for CN=${CN}"
echo "Run ./install.sh so the key is handed to the Unbound uid."
