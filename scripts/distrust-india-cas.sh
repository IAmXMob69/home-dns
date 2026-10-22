#!/usr/bin/env bash
# Distrust Indian licensed CA roots in the system trust store.
# Each root is matched by label and must also match its pinned SHA-256
# fingerprint, so nothing else can end up on the blocklist. Safe to re-run.
#
#   ./scripts/distrust-india-cas.sh           apply (calls sudo where needed)
#   ./scripts/distrust-india-cas.sh --check   report only, changes nothing
#
# Arch and Fedora: blocklist under trust-source / ca-trust, then update-ca-trust.
# Debian and Ubuntu: deselect the file in /etc/ca-certificates.conf, then
# update-ca-certificates. Firefox on these systems follows the system store.
#
# The eMudhra emSign roots are the only Indian-owned roots in the Mozilla
# bundle that distributions ship. The CCA India roots (2011, 2014, 2015, 2022)
# and the CAs under them are not in public browser or OS stores, so there is
# nothing to distrust for them unless they were imported by hand.
set -euo pipefail

# label|sha256 (no colons, upper case). eMudhra emSign roots.
ROOTS=(
  "emSign Root CA - G1|40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367"
  "emSign Root CA - C1|125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F"
  "emSign ECC Root CA - G3|86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
  "emSign ECC Root CA - C3|BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3"
)

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

die() { echo "distrust: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing $1"; }
SUDO=()
[[ "$(id -u)" -ne 0 ]] && SUDO=(sudo)

fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'a-f' 'A-F'
}
file_name() { local n="${1// /_}"; echo "$n"; }

# Prints "distrusted", "trusted" or "absent" for a label (p11-kit systems).
trust_state() {
  local label="$1"
  trust list | awk -v l="label: $label" '
    /^pkcs11:/ { inblk = 0 }
    { line = $0; sub(/^[ \t]+/, "", line) }
    line == l { inblk = 1; next }
    inblk && !found && line ~ /^trust:/ { print $2; found = 1 }
    END { if (!found) print "absent" }'
}

need openssl
if [[ -d /etc/ca-certificates/trust-source || -d /etc/pki/ca-trust/source ]]; then
  need trust
  if [[ -d /etc/ca-certificates/trust-source ]]; then
    BLOCK=/etc/ca-certificates/trust-source/blocklist
  else
    BLOCK=/etc/pki/ca-trust/source/blocklist
  fi
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  changed=0
  for entry in "${ROOTS[@]}"; do
    label="${entry%%|*}" pin="${entry##*|}"
    state="$(trust_state "$label")"
    dest="$BLOCK/$(file_name "$label").pem"
    if [[ "$state" == "distrusted" ]]; then
      echo "ok       $label (already distrusted)"
      continue
    fi
    if [[ "$state" == "absent" ]]; then
      echo "ok       $label (not in the store)"
      continue
    fi
    pem="$work/$(file_name "$label").pem"
    trust extract --overwrite --format=pem-bundle \
      --filter="pkcs11:object=${label// /%20};type=cert" "$pem"
    # The store can hold the same root more than once; every copy must match.
    rm -f "$work"/part-*.pem
    awk -v d="$work" '/BEGIN CERTIFICATE/ { n++ } n { print > (d "/part-" n ".pem") }' "$pem"
    parts=("$work"/part-*.pem)
    [[ -f "${parts[0]}" ]] || die "$label: nothing extracted, refusing"
    for part in "${parts[@]}"; do
      [[ "$(fp_of "$part")" == "$pin" ]] \
        || die "$label: fingerprint does not match the pinned value, refusing"
    done
    pem="${parts[0]}"
    if [[ $CHECK -eq 1 ]]; then
      echo "TRUSTED  $label (would blocklist)"
      continue
    fi
    "${SUDO[@]}" install -D -m 644 "$pem" "$dest"
    echo "blocked  $label"
    changed=1
  done
  if [[ $changed -eq 1 ]]; then
    "${SUDO[@]}" update-ca-trust
    for entry in "${ROOTS[@]}"; do
      label="${entry%%|*}"
      state="$(trust_state "$label")"
      [[ "$state" == "distrusted" || "$state" == "absent" ]] \
        || die "$label still shows as $state after update-ca-trust"
    done
    echo "verified: every pinned root is distrusted or absent"
  fi
elif [[ -f /etc/ca-certificates.conf ]]; then
  need update-ca-certificates
  changed=0
  for entry in "${ROOTS[@]}"; do
    label="${entry%%|*}" pin="${entry##*|}"
    rel="mozilla/$(file_name "$label").crt"
    src="/usr/share/ca-certificates/$rel"
    if [[ ! -f "$src" ]]; then
      echo "ok       $label (not shipped)"
      continue
    fi
    [[ "$(fp_of "$src")" == "$pin" ]] \
      || die "$label: fingerprint does not match the pinned value, refusing"
    if grep -qxF "!$rel" /etc/ca-certificates.conf; then
      echo "ok       $label (already deselected)"
      continue
    fi
    if [[ $CHECK -eq 1 ]]; then
      echo "TRUSTED  $label (would deselect)"
      continue
    fi
    "${SUDO[@]}" sed -i "\\|^${rel}\$|d" /etc/ca-certificates.conf
    echo "!$rel" | "${SUDO[@]}" tee -a /etc/ca-certificates.conf >/dev/null
    echo "blocked  $label"
    changed=1
  done
  if [[ $changed -eq 1 ]]; then
    "${SUDO[@]}" update-ca-certificates --fresh >/dev/null
    for entry in "${ROOTS[@]}"; do
      label="${entry%%|*}"
      [[ ! -e "/etc/ssl/certs/$(file_name "$label").pem" ]] \
        || die "$label is still linked in /etc/ssl/certs"
    done
    echo "verified: no pinned root is left in /etc/ssl/certs"
  fi
else
  die "unsupported trust store layout"
fi
