# Host settings for the shell tools: the environment first, then
# KEY=VALUE lines in ${PIHOLE_ENV_FILE:-<checkout>/.env}.
# `need KEY "hint"` exits 2 with a plain-English message when KEY is unset
# or still a placeholder copied from .env.example.
# shellcheck shell=bash

_settings_file="${PIHOLE_ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env}"

# setting KEY [DEFAULT]: print the value.
setting() {
  local key="$1" def="${2:-}" val="${!1:-}"
  if [[ -z "${val}" && -r "${_settings_file}" ]]; then
    val="$(sed -n "s/^[[:space:]]*\(export[[:space:]]\+\)\?${key}=//p" "${_settings_file}" | tail -n1)"
    val="${val%$'\r'}"
    val="${val#[\"\']}"
    val="${val%[\"\']}"
  fi
  printf '%s' "${val:-${def}}"
}

# is_placeholder VALUE: true for empty or example values.
is_placeholder() {
  local v="${1,,}"
  [[ -z "${v// /}" || "${v}" == *your-* || "${v}" == *your_* || "${v}" == *change-me* \
    || "${v}" == *x.x* || "${v}" == *.x ]]
}

# need KEY "what it is": set KEY in this shell, or exit 2 explaining it.
need() {
  local key="$1" what="$2" val
  val="$(setting "${key}")"
  if is_placeholder "${val}"; then
    printf '%s: %s is not set. %s\nAdd %s=... to .env (see .env.example) or export it, then run this again.\n' \
      "$(basename "$0")" "${key}" "${what}" "${key}" >&2
    exit 2
  fi
  printf -v "${key}" '%s' "${val}"
}

# Hints shared by several tools.
# shellcheck disable=SC2034
HINT_WIFI_CON="It is the NetworkManager connection this PC uses for its LAN (list: nmcli -t -f NAME,DEVICE connection show --active)."
# shellcheck disable=SC2034
HINT_WIFI_DEV="It is the network device of that connection, e.g. wlan0 or eth0 (list: nmcli device)."
# shellcheck disable=SC2034
HINT_DOT_NAME="It is the name in the DoT certificate, e.g. the MagicDNS name from tailscale status, or pihole.lan with the self-signed cert."
# shellcheck disable=SC2034
HINT_USER="It is the login that owns the checkout (run with sudo so SUDO_USER is set, or set PIHOLE_USER)."

# need_owner: set USER_NAME to PIHOLE_USER, else SUDO_USER, or exit 2.
need_owner() {
  USER_NAME="$(setting PIHOLE_USER "${SUDO_USER:-}")"
  if [[ -z "${USER_NAME}" || "${USER_NAME}" == root ]]; then
    printf '%s: PIHOLE_USER is not set. %s\nAdd PIHOLE_USER=... to .env (see .env.example) or export it, then run this again.\n' \
      "$(basename "$0")" "${HINT_USER}" >&2
    exit 2
  fi
}
