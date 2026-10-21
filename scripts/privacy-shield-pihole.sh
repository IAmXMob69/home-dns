#!/usr/bin/env bash
# Load telemetry/analytics deny rules into a Pi-hole group you can toggle:
# Group management → Groups → Data collection halt
# Goes through the Pi-hole v6 API (never writes gravity.db while FTL runs).
# Only touches deny entries whose comment starts with "privacy-shield: ".
#   ./scripts/privacy-shield-pihole.sh [--dry-run]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TSV="$ROOT/privacy-shield/privacy-shield.tsv"
if [[ ! -f "$TSV" ]]; then
  echo "missing $TSV" >&2
  exit 1
fi
python3 "$ROOT/scripts/lib/pihole_groups.py" \
  --group "Data collection halt" \
  --description "On = block telemetry, analytics, crash-report, and tracker endpoints. Off = those names work again. Use this switch." \
  --tag "privacy-shield: " \
  --tsv "$TSV" "$@"
echo "In Pi-hole: Group management → Groups → Data collection halt"
