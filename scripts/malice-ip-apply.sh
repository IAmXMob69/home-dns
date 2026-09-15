#!/usr/bin/env bash
# Drop FireHOL level1 malicious IPv4 (inbound/outbound). Linux nftables.
# Always allows loopback, RFC1918, and Tailscale CGNAT.
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run as root: sudo $0" >&2
  exit 1
fi
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
curl -fsSL --max-time 40 -o "$TMP" \
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
python3 - "$TMP" << 'PY'
import ipaddress, sys
from pathlib import Path
skip=[ipaddress.ip_network(x) for x in (
    "0.0.0.0/8","10.0.0.0/8","127.0.0.0/8","169.254.0.0/16",
    "172.16.0.0/12","192.168.0.0/16","100.64.0.0/10")]
keep=[]
for line in Path(sys.argv[1]).read_text().splitlines():
    line=line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        n=ipaddress.ip_network(line, strict=False)
    except ValueError:
        continue
    if n.version!=4:
        continue
    if any(n.overlaps(s) for s in skip):
        continue
    keep.append(str(n))
def elems(xs, per=40):
    return ",\n".join("      "+", ".join(xs[i:i+per]) for i in range(0,len(xs),per))
nft=f'''#!/usr/bin/nft -f
destroy table inet malice_block
table inet malice_block {{
  set bad4 {{
    type ipv4_addr
    flags interval
    auto-merge
    elements = {{
{elems(keep)}
    }}
  }}
  set pass4 {{
    type ipv4_addr
    flags interval
    auto-merge
    elements = {{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }}
  }}
  chain input {{
    type filter hook input priority filter - 4; policy accept;
    ip saddr @pass4 accept
    ip saddr @bad4 drop
  }}
  chain output {{
    type filter hook output priority filter - 4; policy accept;
    ip daddr @pass4 accept
    ip daddr @bad4 drop
  }}
}}
'''
Path("/etc/nftables.d/malice-block.nft").write_text(nft)
print("cidrs", len(keep))
PY
mkdir -p /etc/nftables.d
if ! grep -q malice-block.nft /etc/nftables.conf 2>/dev/null; then
  printf '\ninclude "/etc/nftables.d/malice-block.nft"\n' >> /etc/nftables.conf
fi
nft -f /etc/nftables.d/malice-block.nft
echo "malice-block applied"
