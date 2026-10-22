#!/usr/bin/env bash
# Refresh the Tailscale Let's Encrypt cert used by dnsdist (DoT/DoH).
set -euo pipefail
# Go build if present (go/bin/refresh-dot-cert); PIHOLE_NO_GO=1 forces the shell body below.
_go_bin="$(cd "$(dirname "$0")/.." && pwd)/go/bin/refresh-dot-cert"
if [[ -z "${PIHOLE_NO_GO:-}" && -x "${_go_bin}" ]]; then
  PIHOLE_ARGV0="$0" PIHOLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" exec "${_go_bin}" "$@"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${DOT_AUTH_NAME:-your-host.your-tailnet.ts.net}"
if [[ "${NAME}" == "your-host.your-tailnet.ts.net" ]]; then
  echo "Set DOT_AUTH_NAME to this node's MagicDNS name (tailscale status --self)." >&2
  exit 1
fi
CERT="${ROOT}/dnsdist/tls.pem"
KEY="${ROOT}/dnsdist/tls.key"
umask 077
mkdir -p "${ROOT}/dnsdist"

TMP_CERT="$(mktemp "${ROOT}/dnsdist/.tls.pem.XXXXXX")"
TMP_KEY="$(mktemp "${ROOT}/dnsdist/.tls.key.XXXXXX")"
trap 'rm -f "${TMP_CERT}" "${TMP_KEY}"' EXIT
if ! tailscale cert --cert-file "${TMP_CERT}" --key-file "${TMP_KEY}" "${NAME}"; then
  echo "tailscale cert failed; leaving existing ${CERT}" >&2
  exit 1
fi
chmod 644 "${TMP_CERT}"
chmod 600 "${TMP_KEY}"
# Key is 0600 and owned by dnsdist's uid (pdns, 953). Rename works even
# though the old key belongs to 953; docker does the chown (no sudo).
mv -f "${TMP_CERT}" "${CERT}"
mv -f "${TMP_KEY}" "${KEY}"
trap - EXIT
docker run --rm --network none --user 0 --entrypoint /bin/sh \
  -v "${ROOT}/dnsdist:/k" powerdns/dnsdist-19:latest \
  -c 'chown 953:953 /k/tls.key && chmod 600 /k/tls.key'

cd "${ROOT}"
if docker compose ps --status running --services 2>/dev/null | grep -qx dnsdist; then
  docker compose restart dnsdist
fi
echo "Refreshed DoT/DoH cert for ${NAME}"
