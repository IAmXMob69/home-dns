#!/usr/bin/env bash
# Fresh host or recreate: copy CA bundle, DoT cert, start DNS chain.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Wrote .env from .env.example — edit LAN_IPV4 / passwords before relying on this."
fi

pick_ca() {
  local p
  for p in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/cert.pem \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ca-certificates/extracted/tls-ca-bundle.pem
  do
    if [[ -r "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

CA="$(pick_ca)" || { echo "No host CA bundle found" >&2; exit 1; }
cp "$CA" "$ROOT/unbound/ca-certificates.crt"
chmod 644 "$ROOT/unbound/ca-certificates.crt"

if [[ ! -f unbound/tls.pem || ! -f unbound/tls.key ]]; then
  chmod +x scripts/gen-dot-cert.sh
  ./scripts/gen-dot-cert.sh pihole.lan
fi
chmod 644 unbound/tls.key unbound/tls.pem

mkdir -p etc-pihole
chmod +x scripts/*.sh install.sh

docker compose up -d --force-recreate dnscrypt unbound pihole
docker compose ps
echo
echo "Probe Unbound:"
docker exec unbound drill @127.0.0.1 dnssec.works || true
echo
echo "Geo-lock is off until you:"
echo "  cp geolock/settings.env.example geolock/settings.env"
echo "  # set GEOLOCK_ENABLED=1"
echo "  sudo ./scripts/geolock-apply.sh"
