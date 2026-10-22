#!/usr/bin/env bash
# Publish Pi-hole DNS/admin on this host's Tailscale IPv4 (100.x).
# Never binds 0.0.0.0 or [::]. Requires: tailscale up --accept-dns=false.
set -euo pipefail
# Go build if present (go/bin/publish-tailscale-dns); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")" && pwd)/go/bin/publish-tailscale-dns"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")" && pwd)" exec "${_go_bin}" "$@"
fi

PIHOLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE="${PIHOLE_DIR}/docker-compose.tailscale.yml"
ENV_FILE="${PIHOLE_DIR}/.env"
# shellcheck source=lib/settings.sh
source "${PIHOLE_DIR}/lib/settings.sh"
need LAN_IPV4 "It is this PC's fixed LAN IPv4 address."
# Go build if present, else the Python original.
if [[ -x "${PIHOLE_DIR}/go/bin/dns-probe" ]]; then PROBE=("${PIHOLE_DIR}/go/bin/dns-probe"); else PROBE=(python3 "${PIHOLE_DIR}/dns-probe.py"); fi

is_tailscale_v4() {
  [[ "$1" =~ ^100\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]
}

upsert_env() {
  local key="$1" val="$2"
  python3 - "$ENV_FILE" "$key" "$val" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
key, val = sys.argv[2], sys.argv[3]
lines = path.read_text().splitlines() if path.exists() else []
out, found = [], False
for line in lines:
    if line.startswith(key + "="):
        out.append(f"{key}={val}")
        found = True
    else:
        out.append(line)
if not found:
    if out and out[-1] != "":
        out.append("")
    out.append(f"{key}={val}")
path.write_text("\n".join(out) + "\n")
PY
  chmod 600 "${ENV_FILE}"
}

wait_for_ts_ip() {
  local ip=""
  for _ in $(seq 1 60); do
    ip="$(tailscale ip -4 2>/dev/null || true)"
    if is_tailscale_v4 "${ip}"; then
      printf '%s\n' "${ip}"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: no Tailscale IPv4 yet. Run: tailscale up --accept-dns=false" >&2
  return 1
}

TS_IP="$(wait_for_ts_ip)"

# docker-compose.tailscale.yml ships with the repo and reads TAILSCALE_IPV4
# and LAN_IPV4 from .env, so only .env changes here.
if [[ ! -f "${OVERRIDE}" ]]; then
  echo "ERROR: ${OVERRIDE} is missing. It ships with the repo; restore it with: git checkout docker-compose.tailscale.yml" >&2
  exit 1
fi

upsert_env TAILSCALE_IPV4 "${TS_IP}"
upsert_env COMPOSE_FILE "docker-compose.yml:docker-compose.tailscale.yml"

cd "${PIHOLE_DIR}"
docker compose up -d pihole dnsdist

echo "==> Waiting for DNS on ${TS_IP}"
ready=0
for _ in $(seq 1 30); do
  if "${PROBE[@]}" example.com "${TS_IP}" >/tmp/pihole-ts-probe.log 2>&1; then
    cat /tmp/pihole-ts-probe.log
    ready=1
    break
  fi
  sleep 1
done
if [[ ${ready} -ne 1 ]]; then
  cat /tmp/pihole-ts-probe.log >&2 || true
  docker compose logs --tail 40 pihole >&2 || true
  exit 1
fi

echo "Tailscale DNS: ${TS_IP}"
ss -tuln | grep -E ':53 ' || true
