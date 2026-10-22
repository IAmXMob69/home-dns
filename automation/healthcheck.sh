#!/usr/bin/env bash
# Periodic Pi-hole + Unbound health check with rate-limited desktop notify.
set -euo pipefail
# Go build if present (go/bin/healthcheck); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/healthcheck"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${ROOT}/logs/healthcheck.log"
STATE_DIR="${ROOT}/state"
HEALTH_JSON="${STATE_DIR}/health.json"
NOTIFY_JSON="${STATE_DIR}/health-notify.json"

mkdir -p "${ROOT}/logs" "${STATE_DIR}"
exec >>"${LOG}" 2>&1

# shellcheck source=lib/docker_cmd.sh
source "${ROOT}/lib/docker_cmd.sh"

ts_now() { date -Iseconds; }

notify_desktop() {
  local body="$1"
  DISPLAY=:0.0 DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}" \
    notify-send -a Pi-hole "Pi-hole healthcheck" "${body}" >/dev/null 2>&1 || true
}

issues=()
gravity=0
mode="unknown"
ok=true

echo "[$(ts_now)] healthcheck start"

# --- containers: pihole + unbound running/healthy ---
ps_out="$(docker_cmd compose -f "${ROOT}/docker-compose.yml" -f "${ROOT}/docker-compose.tailscale.yml" --env-file "${ROOT}/.env" ps 2>/dev/null || true)"
for svc in pihole unbound; do
  if ! echo "${ps_out}" | grep -E "(^|[[:space:]])${svc}([[:space:]]|$)" >/dev/null 2>&1; then
    issues+=("${svc}_missing")
    ok=false
    continue
  fi
  line="$(echo "${ps_out}" | grep -E "(^|[[:space:]])${svc}([[:space:]]|$)" | head -1 || true)"
  if echo "${line}" | grep -qiE 'unhealthy|Exit|exited|created|dead'; then
    issues+=("${svc}_unhealthy")
    ok=false
  elif ! echo "${line}" | grep -qiE 'Up|running|healthy'; then
    issues+=("${svc}_not_running")
    ok=false
  fi
done

# --- gravity_count ---
if count_raw="$(docker_cmd exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" 2>/dev/null)"; then
  gravity="${count_raw//$'\r'/}"
  gravity="${gravity%%$'\n'*}"
elif [[ -f "${ROOT}/etc-pihole/gravity.db" ]]; then
  gravity="$(sqlite3 "${ROOT}/etc-pihole/gravity.db" "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';" 2>/dev/null || echo 0)"
else
  gravity=0
fi
gravity="${gravity:-0}"
if ! [[ "${gravity}" =~ ^[0-9]+$ ]]; then
  gravity=0
fi
if [[ "${gravity}" -lt 100000 ]]; then
  if [[ "${gravity}" -eq 0 ]]; then
    issues+=("gravity_missing_or_zero")
  else
    issues+=("gravity_low:${gravity}")
  fi
  ok=false
fi

# --- watchdog mode ---
if [[ -f "${STATE_DIR}/watchdog.json" ]]; then
  mode="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("mode","unknown"))' "${STATE_DIR}/watchdog.json" 2>/dev/null || echo unknown)"
  if [[ "${mode}" == "cloudflare" ]]; then
    issues+=("watchdog_cloudflare")
    ok=false
  fi
else
  mode="unknown"
  issues+=("watchdog_state_missing")
  ok=false
fi

# --- disk free on project root (>= 8GB) ---
avail_kb="$(df -Pk "${ROOT}" | awk 'NR==2{print $4}')"
if [[ -z "${avail_kb}" ]] || [[ "${avail_kb}" -lt 8388608 ]]; then
  issues+=("disk_low:${avail_kb:-0}KB")
  ok=false
fi

# --- unbound DNSSEC probe ---
if ! docker_cmd exec unbound drill-hc @127.0.0.1 dnssec.works >/dev/null 2>&1 \
   && ! docker_cmd exec unbound drill @127.0.0.1 dnssec.works >/dev/null 2>&1; then
  issues+=("unbound_dnssec_fail")
  ok=false
fi

# --- optional admin UI ---
if ! curl -fsS --max-time 5 http://127.0.0.1/admin/ >/dev/null 2>&1; then
  issues+=("admin_ui_unreachable")
  ok=false
fi

if [[ ${#issues[@]} -eq 0 ]]; then
  issues_json='[]'
else
  issues_json="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${issues[@]}")"
fi

ok_str=false
[[ "${ok}" == "true" ]] && ok_str=true

python3 -c '
import json, sys
from pathlib import Path
ok = sys.argv[1] == "true"
gravity = int(sys.argv[2])
mode = sys.argv[3]
ts = sys.argv[4]
issues = json.loads(sys.argv[5])
path = Path(sys.argv[6])
data = {"ok": ok, "ts": ts, "gravity": gravity, "mode": mode, "issues": issues}
path.write_text(json.dumps(data, separators=(",", ":")))
print(json.dumps(data))
' "${ok_str}" "${gravity}" "${mode}" "$(ts_now)" "${issues_json}" "${HEALTH_JSON}"

echo "[$(ts_now)] healthcheck done ok=${ok_str} gravity=${gravity} mode=${mode} issues=${issues_json}"

# Rate-limited notify: same issues hash within 2h => skip
if [[ ${#issues[@]} -gt 0 ]]; then
  hash="$(printf '%s\n' "${issues[@]}" | sha256sum | awk '{print $1}')"
  should_notify=1
  if [[ -f "${NOTIFY_JSON}" ]]; then
    eval "$(python3 -c '
import json, sys
from datetime import datetime, timezone
from pathlib import Path
p = Path(sys.argv[1])
want = sys.argv[2]
try:
    d = json.loads(p.read_text())
    prev_hash = d.get("hash", "")
    prev_ts = d.get("ts", "")
    age = 999999
    if prev_ts:
        t = datetime.fromisoformat(prev_ts)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        age = int((datetime.now(timezone.utc) - t.astimezone(timezone.utc)).total_seconds())
    print(f"prev_hash={prev_hash!r}")
    print(f"age={age}")
    if prev_hash == want and age < 7200:
        print("should_notify=0")
    else:
        print("should_notify=1")
except Exception:
    print("should_notify=1")
' "${NOTIFY_JSON}" "${hash}")"
  fi
  if [[ "${should_notify}" -eq 0 ]]; then
    echo "[$(ts_now)] notify suppressed (same issues within 2h)"
  else
    body="$(printf '%s; ' "${issues[@]}")"
    body="${body%; }"
    notify_desktop "${body}"
    python3 -c '
import json, sys
from pathlib import Path
Path(sys.argv[3]).write_text(json.dumps({
    "hash": sys.argv[1],
    "ts": sys.argv[2],
    "issues": json.loads(sys.argv[4]),
}))
' "${hash}" "$(ts_now)" "${NOTIFY_JSON}" "${issues_json}"
    echo "[$(ts_now)] notified: ${body}"
  fi
fi

if [[ "${ok_str}" == "true" ]]; then
  exit 0
fi
exit 1
