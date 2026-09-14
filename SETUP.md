# Setup guide

Build the same shape of stack I run: Pi-hole blocks on the LAN, Unbound does DNSSEC / local DoT, dnscrypt-proxy does anonymized upstream. Admin UI stays on loopback; remote UI is Tailscale Serve.

## What you need

- Linux host with Docker + Compose v2
- A **stable LAN IPv4** on that host (static DHCP or NetworkManager manual)
- Optional: Tailscale for remote admin HTTPS
- Optional: UFW or equivalent firewall

You do **not** need my passwords, Tailscale IPs, Wi‑Fi name, or TLS private key. Generate your own.

## 1. Clone and configure

```bash
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
cp .env.example .env
$EDITOR .env
```

Set at least:

- `FTLCONF_webserver_api_password`
- `LAN_IPV4` / `LAN_CIDR` / `LAN_GATEWAY`
- `TAILSCALE_IPV4` if you use Tailscale (`tailscale ip -4`)

Edit `docker-compose.yml` binds if your LAN is not `192.168.1.0/24` — search for `${LAN_IPV4}` and the Unbound `access-control` line in `unbound/custom.conf.d/hardening.conf`.

## 2. DNS-over-TLS certificate

```bash
./scripts/gen-dot-cert.sh pihole.lan
```

Phone Private DNS / DoT clients will need to trust this cert (or use a name you control).

## 3. Start the DNS chain

```bash
mkdir -p etc-pihole
docker compose up -d dnscrypt unbound pihole
docker compose ps
```

Check:

```bash
docker exec unbound drill @127.0.0.1 dnssec.works
dig @${LAN_IPV4} example.com +short
curl -fsS http://127.0.0.1/admin/login >/dev/null && echo "admin UI up"
```

## 4. Point the LAN at Pi-hole

On the router: set DHCP DNS to your host `LAN_IPV4` only.

On the host itself: use `127.0.0.1` as DNS (so the box still resolves if Docker is restarting). Example NetworkManager:

```bash
nmcli connection modify YOUR_WIFI_CONNECTION \
  ipv4.dns 127.0.0.1 \
  ipv4.ignore-auto-dns yes
nmcli connection up YOUR_WIFI_CONNECTION
```

## 5. Firewall (do not skip)

Allow DNS **only from your LAN**, never from the world:

```bash
# UFW example — replace with your LAN CIDR
sudo ufw allow from 192.168.1.0/24 to any port 53 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 53 proto udp
# Do NOT: ufw allow 53
# Do NOT publish admin 80/443 on the LAN or WAN
```

Compose already binds admin to `127.0.0.1:80` / `127.0.0.1:443` only.

Never bind DNS to `[::]` on a dual-stack host. Use a specific `LAN_IPV6` or skip IPv6 DNS.

## 6b. Geo-location lock (optional)

Off by default. LAN, loopback, and Tailscale CGNAT (`100.64.0.0/10`) always pass.

```bash
cp geolock/settings.env.example geolock/settings.env
# GEOLOCK_ENABLED=1
# GEOLOCK_MODE=allow and GEOLOCK_ALLOW_COUNTRIES=US,DE
# or GEOLOCK_MODE=deny and GEOLOCK_DENY_COUNTRIES=...
sudo ./scripts/geolock-apply.sh
```

Do not commit `geolock/settings.env`.

## 6. Blocklists

In the Pi-hole UI (`http://127.0.0.1/admin/`):

1. Add the public lists you want (StevenBlack, OISD small, Firebog, etc.)
2. Gravity update
3. Keep a small allowlist for things CNAME inspection breaks (social CDNs, etc.)

This repo does **not** ship my live gravity database or allowlist.

## 7. Tailscale admin (optional)

Keep Tailscale DNS **off** on the Pi-hole host if this box *is* your DNS (`tailscale set --accept-dns=false`), otherwise MagicDNS can fight Pi-hole.

Serve the UI:

```bash
sudo tailscale serve --bg http://127.0.0.1:80
```

Open `https://YOURHOST.YOURTAILNET.ts.net/admin/` from another Tailscale device.

When `TAILSCALE_IPV4` is set:

```bash
# .env
COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml
docker compose up -d pihole
```

## 8. Monitoring (optional)

```bash
# .env must include GRAFANA_ADMIN_PASSWORD
docker compose up -d pihole-exporter prometheus grafana
```

UI: `http://127.0.0.1:3000` (Grafana), `http://127.0.0.1:9090` (Prometheus). Not published off-box.

## Architecture reminders

```
LAN clients → Pi-hole :53 → Unbound → dnscrypt-proxy → internet
                ↑
         blocklists / rate limit

Admin → 127.0.0.1:80 → (optional) Tailscale Serve HTTPS
```

- FTL upstream must stay `unbound` only — do not add `1.1.1.1` there or ads bypass the chain.
- FTL DNSSEC off when Unbound already validates.
- Rate limit aggressive clients (`1000/60` is a reasonable starting point).

## Hardening checklist

- [ ] No `0.0.0.0` / `[::]` on DNS or admin publishes
- [ ] `.env` mode `600`, never committed
- [ ] `unbound/tls.key` mode `600`, never committed
- [ ] UFW (or nftables) allows `:53` from LAN only
- [ ] Admin not port-forwarded on the router
- [ ] Host DNS is `127.0.0.1`, LAN clients use `LAN_IPV4`

## Firefox note

On the Pi-hole host, use `http://127.0.0.1/admin/`.  
`http://pi.hole` often resolves to the **container** bridge IP, which does not serve the published admin ports. Pin in `/etc/hosts` if you want the pretty name:

```
127.0.0.1 pi.hole pihole.lan
```
