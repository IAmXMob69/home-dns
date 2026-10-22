#!/usr/bin/env bash
# Install local Pi-hole deny rules that block common telemetry, analytics,
# crash-reporting, attribution, and session-replay endpoints.
set -euo pipefail
# Go build if present (go/bin/install-privacy-shield); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/install-privacy-shield"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="${1:-${ROOT}/privacy-shield/privacy-shield.tsv}"
SQL="$(mktemp)"
trap 'rm -f "${SQL}"' EXIT

if [[ ! -f "${RULES}" ]]; then
  echo "privacy shield rules not found: ${RULES}" >&2
  exit 1
fi

# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"

sql_escape() {
  local value="$1"
  value=${value//\'/\'\'}
  printf "%s" "${value}"
}

{
  echo "BEGIN;"
  echo "INSERT OR IGNORE INTO \"group\" (id, enabled, name) VALUES (0, 1, 'Network');"

  installed=0
  while IFS=$'\t' read -r type rule comment extra; do
    [[ -z "${type:-}" || "${type:0:1}" == "#" ]] && continue
    if [[ -n "${extra:-}" ]]; then
      echo "invalid extra tab-separated field in rule: ${rule}" >&2
      exit 1
    fi
    if [[ "${type}" != "1" && "${type}" != "3" ]]; then
      echo "invalid rule type '${type}' for ${rule}" >&2
      exit 1
    fi
    if [[ -z "${rule:-}" || -z "${comment:-}" ]]; then
      echo "invalid empty rule/comment in ${RULES}" >&2
      exit 1
    fi

    rule_sql="$(sql_escape "${rule}")"
    comment_sql="$(sql_escape "privacy-shield: ${comment}")"
    cat <<SQL
INSERT INTO domainlist (type, domain, enabled, comment)
VALUES (${type}, '${rule_sql}', 1, '${comment_sql}')
ON CONFLICT(domain, type) DO UPDATE SET
  enabled = 1,
  comment = excluded.comment,
  date_modified = cast(strftime('%s', 'now') as int);
INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id)
SELECT id, 0 FROM domainlist WHERE type = ${type} AND domain = '${rule_sql}';
SQL
    installed=$((installed + 1))
  done <"${RULES}"

  echo "COMMIT;"
  echo "SELECT COUNT(*) AS privacy_shield_enabled FROM domainlist WHERE enabled=1 AND comment LIKE 'privacy-shield:%';"
} >"${SQL}"

echo "Installing Pi-hole privacy shield from ${RULES}"
docker_cmd exec -i pihole pihole-FTL sqlite3 /etc/pihole/gravity.db <"${SQL}"
docker_cmd exec pihole pihole reloaddns
echo "Privacy shield installed (${installed} rules processed)."
