#!/usr/bin/env bash
# Generate a strong admin-panel TLS certificate for Pi-hole v6 and print the
# compose / pihole.toml knobs that lock the web server to TLS 1.2+ with AEAD
# ciphers only. Does not restart containers and does not need sudo.
#
# Usage:
#   ./scripts/harden-pihole-tls.sh              # write cert, print apply steps
#   ./scripts/harden-pihole-tls.sh --print      # show recommended settings only
#
# Environment (all optional):
#   PIHOLE_DIR       checkout that runs docker compose (default: this repo)
#   PIHOLE_ETC       host path of the etc-pihole volume (default: $PIHOLE_DIR/etc-pihole)
#   ADMIN_TLS_CN     certificate CN (default: pihole.lan)
#   ADMIN_TLS_DNS    extra DNS SANs, comma-separated (e.g. your-host.your-tailnet.ts.net)
#   ADMIN_TLS_IP     extra IP SANs, comma-separated (e.g. 127.0.0.1,LAN_IPV4,TAILSCALE_IPV4)
#   ADMIN_TLS_DAYS   validity in days (default: 825)
#   ADMIN_TLS_ALG    ecdsa-p384 (default) or rsa-4096
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PRINT_ONLY=0
[[ "${1:-}" == "--print" ]] && PRINT_ONLY=1

PIHOLE_DIR="${PIHOLE_DIR:-$ROOT}"
PIHOLE_ETC="${PIHOLE_ETC:-$PIHOLE_DIR/etc-pihole}"
CN="${ADMIN_TLS_CN:-pihole.lan}"
DAYS="${ADMIN_TLS_DAYS:-825}"
ALG="${ADMIN_TLS_ALG:-ecdsa-p384}"

# Recommended CivetWeb / mbedTLS options for Pi-hole FTL v6.3+.
# ssl_protocol_version=4 => TLS 1.2 and above (TLS 1.0/1.1 off).
# Cipher list is AEAD-only: no CBC, no SHA-1 HMAC suites.
ADV_OPTS='["ssl_protocol_version=4","ssl_cipher_list=TLS1-3-AES-256-GCM-SHA384:TLS1-3-CHACHA20-POLY1305-SHA256:TLS1-3-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"]'

print_settings() {
  cat <<SETTINGS
Recommended Pi-hole admin TLS settings
--------------------------------------
In docker-compose.yml (or matching FTLCONF_* env):

  FTLCONF_webserver_port: "80or,443os"
  FTLCONF_webserver_tls_validity: "0"
  FTLCONF_webserver_advancedOpts: '${ADV_OPTS}'

Meaning:
  - 80or,443os  HTTP on 80 redirects to HTTPS when the cert is present
  - validity 0  Pi-hole will not overwrite a custom cert you install
  - advancedOpts  TLS 1.2+ only, AEAD cipher suites only (mbedTLS names)

Cert path inside the container: /etc/pihole/tls.pem
Host path (etc-pihole volume):  ${PIHOLE_ETC}/tls.pem
SETTINGS
}

if [[ "$PRINT_ONLY" -eq 1 ]]; then
  print_settings
  exit 0
fi

command -v openssl >/dev/null 2>&1 || { echo "harden-pihole-tls: openssl not found" >&2; exit 1; }
mkdir -p "$PIHOLE_ETC"
umask 077

# Build SAN list. Always include pi.hole + CN. Never bake a real Tailscale
# hostname into the repo; pass it at generate time via ADMIN_TLS_DNS.
SAN="DNS:pi.hole,DNS:${CN}"
if [[ -n "${ADMIN_TLS_DNS:-}" ]]; then
  IFS=',' read -r -a dns_sans <<< "${ADMIN_TLS_DNS}"
  for d in "${dns_sans[@]}"; do
    d="${d// /}"
    [[ -n "$d" ]] || continue
    SAN="${SAN},DNS:${d}"
  done
fi
if [[ -n "${ADMIN_TLS_IP:-}" ]]; then
  IFS=',' read -r -a ip_sans <<< "${ADMIN_TLS_IP}"
  for ip in "${ip_sans[@]}"; do
    ip="${ip// /}"
    [[ -n "$ip" ]] || continue
    SAN="${SAN},IP:${ip}"
  done
else
  # Sensible local defaults when the caller did not pass IPs.
  SAN="${SAN},IP:127.0.0.1"
fi

tmp_key="$(mktemp "${PIHOLE_ETC}/.tls.key.XXXXXX")"
tmp_crt="$(mktemp "${PIHOLE_ETC}/.tls.crt.XXXXXX")"
tmp_pem="$(mktemp "${PIHOLE_ETC}/.tls.pem.XXXXXX")"
trap 'rm -f "$tmp_key" "$tmp_crt" "$tmp_pem"' EXIT

case "$ALG" in
  ecdsa-p384|ecdsa|p384)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
      -sha384 -days "$DAYS" -nodes \
      -keyout "$tmp_key" -out "$tmp_crt" \
      -subj "/CN=${CN}/O=home-dns/C=US" \
      -addext "subjectAltName=${SAN}" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth"
    ;;
  rsa-4096|rsa)
    openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
      -keyout "$tmp_key" -out "$tmp_crt" \
      -subj "/CN=${CN}/O=home-dns/C=US" \
      -addext "subjectAltName=${SAN}" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth"
    ;;
  *)
    echo "harden-pihole-tls: unknown ADMIN_TLS_ALG=${ALG} (use ecdsa-p384 or rsa-4096)" >&2
    exit 1
    ;;
esac

# Pi-hole wants a single PEM with CERTIFICATE then PRIVATE KEY.
cat "$tmp_crt" "$tmp_key" > "$tmp_pem"
chmod 600 "$tmp_pem" "$tmp_key"
chmod 644 "$tmp_crt"
cp -f "$tmp_crt" "${PIHOLE_ETC}/tls.crt"
cp -f "$tmp_crt" "${PIHOLE_ETC}/tls_ca.crt"
mv -f "$tmp_pem" "${PIHOLE_ETC}/tls.pem"
rm -f "$tmp_key"
trap - EXIT

echo "Wrote ${PIHOLE_ETC}/tls.pem (${ALG}, ${DAYS} days)"
echo "  CN=${CN}"
echo "  SAN=${SAN}"
echo
print_settings
cat <<'NEXT'

This script only writes the cert under etc-pihole/. It does not edit
docker-compose.yml. Merge the three FTLCONF lines above into your running
compose if they are missing — do not overwrite the whole file (that can wipe
unrelated hardening). Then:

  docker compose up -d pihole

Confirm TLS 1.2+ and that weak CBC suites are gone:

  echo | openssl s_client -connect 127.0.0.1:443 -tls1_2 2>/dev/null | grep -E 'Protocol|Cipher'
  echo | openssl s_client -connect 127.0.0.1:443 -tls1_2 -cipher 'ECDHE-RSA-AES128-SHA' 2>&1 | grep -E 'Cipher|handshake|alert'

Open https://127.0.0.1/admin/ and accept the new certificate once.
NEXT
