#!/usr/bin/env bash
# Generate a local DNS-over-TLS cert for Unbound (LAN Private DNS clients).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/unbound"
CN="${1:-pihole.lan}"
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout "$ROOT/unbound/tls.key" \
  -out "$ROOT/unbound/tls.pem" \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:${CN},DNS:pi.hole"
# 644: Unbound in the container runs as 101:102 and must read the key.
chmod 644 "$ROOT/unbound/tls.key"
chmod 644 "$ROOT/unbound/tls.pem"
echo "Wrote unbound/tls.key and unbound/tls.pem for CN=${CN}"
