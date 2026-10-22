#!/usr/bin/env bash
# Turn off the temporary Pi-hole/Unbound debug window.
# Leaves debug.performance and serve-expired as they were.
set -euo pipefail
# Go build if present (go/bin/debug-window-off); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/debug-window-off"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Go build if present, else the Python original.
if [[ -x "${ROOT}/go/bin/dns-probe" ]]; then PROBE=("${ROOT}/go/bin/dns-probe"); else PROBE=(python3 "${ROOT}/dns-probe.py"); fi
STATE="${ROOT}/state/debug-window.json"
LOG="${ROOT}/logs/debug-window-off.log"
CONF="${ROOT}/unbound/custom.conf.d/hardening.conf"

mkdir -p "${ROOT}/logs"
exec >>"${LOG}" 2>&1
echo "[$(date -Iseconds)] debug-window-off start"

if [[ ! -f "${STATE}" ]]; then
  echo "no state file; nothing to do"
  exit 0
fi

active="$(python3 -c 'import json,sys; print(bool(json.load(open(sys.argv[1])).get("active")))' "${STATE}")"
if [[ "${active}" != "True" ]]; then
  echo "window already inactive"
  exit 0
fi

systemctl --user stop pihole-watchdog.timer || true

set +e
docker exec pihole pihole-FTL --config debug.queries false
docker exec pihole pihole-FTL --config debug.flags false
docker exec pihole pihole-FTL --config debug.resolver false
docker exec pihole pihole-FTL --config debug.status false
docker exec pihole pihole-FTL --config misc.extraLogging false
ftl_rc=$?
set -e
echo "ftl revert rc=${ftl_rc}"

# Never leave the setting that previously took DNS down.
if grep -q 'serve-expired: no' "${CONF}"; then
  sed -i 's/serve-expired: no/serve-expired: yes/' "${CONF}"
fi
if grep -qE 'verbosity: [1-5]' "${CONF}"; then
  python3 - "${CONF}" << 'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
start = text.find("    # Temporary debug window.")
verb = text.find("    verbosity:")
if start != -1 and verb != -1 and start < verb:
    end = text.find("\n", verb)
    text = text[:start] + "    verbosity: 0" + text[end:]
else:
    import re
    text = re.sub(r"verbosity: [1-5]", "verbosity: 0", text, count=1)
path.write_text(text)
PY
  chmod 644 "${CONF}"
  docker restart unbound
  for _ in $(seq 1 20); do
    st="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' unbound 2>/dev/null || echo missing)"
    echo "unbound health=${st}"
    [[ "${st}" == "healthy" ]] && break
    sleep 2
  done
fi

python3 - "${STATE}" << 'PY'
import json, sys
from datetime import datetime
path = sys.argv[1]
data = json.load(open(path))
data["active"] = False
data["reverted"] = datetime.now().astimezone().isoformat(timespec="seconds")
json.dump(data, open(path, "w"), indent=2)
print("state marked inactive")
PY

systemctl --user start pihole-watchdog.timer || true
if "${PROBE[@]}" example.com 127.0.0.1; then
  echo "probe ok"
else
  echo "ERROR: probe failed after revert"
  exit 1
fi
echo "[$(date -Iseconds)] debug-window-off done"
