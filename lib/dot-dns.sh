# Shared host DNS helpers: Pi-hole DoT on loopback, Cloudflare DoT for failover.
# Needs lib/settings.sh. WIFI_CON, WIFI_DEV and DOT_AUTH_NAME come from the
# environment or .env; the script exits with a message when one is missing.
# shellcheck shell=bash
# shellcheck source=lib/settings.sh
source "$(dirname "${BASH_SOURCE[0]}")/settings.sh"

need WIFI_CON "${HINT_WIFI_CON}"
need WIFI_DEV "${HINT_WIFI_DEV}"
if [[ -z "${PIHOLE_DNS:-}" ]]; then
  need DOT_AUTH_NAME "${HINT_DOT_NAME}"
fi
PIHOLE_DNS="${PIHOLE_DNS:-127.0.0.1#${DOT_AUTH_NAME}}"
CLOUDFLARE_DOT_DNS="${CLOUDFLARE_DOT_DNS:-1.1.1.1#cloudflare-dns.com,8.8.8.8#dns.google}"

failover_public_dns() {
  nmcli connection modify "${WIFI_CON}" \
    ipv4.dns "${CLOUDFLARE_DOT_DNS}" \
    connection.dns-over-tls yes
  if ! nmcli device reapply "${WIFI_DEV}" >/dev/null 2>&1; then
    resolvectl dns "${WIFI_DEV}" "1.1.1.1#cloudflare-dns.com" "8.8.8.8#dns.google"
    resolvectl dnsovertls "${WIFI_DEV}" yes
  fi
}

restore_pihole_dns() {
  nmcli connection modify "${WIFI_CON}" \
    ipv4.dns "${PIHOLE_DNS}" \
    ipv6.dns "" \
    ipv4.ignore-auto-dns yes \
    ipv6.ignore-auto-dns yes \
    connection.dns-over-tls yes
  if ! nmcli device reapply "${WIFI_DEV}" >/dev/null 2>&1; then
    resolvectl dns "${WIFI_DEV}" "${PIHOLE_DNS}"
    resolvectl dnsovertls "${WIFI_DEV}" yes
  fi
}
