# Windows setup

Same stack as Linux: Pi-hole on the LAN, Unbound for DNSSEC / DoT, dnscrypt-proxy for anonymized upstream. Admin UI stays on loopback.

## What you need

- Windows 10/11
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with the **WSL2** engine
- A **stable LAN IPv4** on this PC (DHCP reservation or a static address)
- Optional: Git for Windows (gives `openssl` + a CA bundle)

You do **not** commit `.env`, TLS keys, or `etc-pihole/`.

## 1. Clone and configure

```powershell
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
copy .env.example .env
notepad .env
```

Set at least:

- `FTLCONF_webserver_api_password`
- `LAN_IPV4` / `LAN_CIDR` / `LAN_GATEWAY` (this PC’s IPv4, not `0.0.0.0`)

Find the LAN IPv4:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
  Select-Object IPAddress, InterfaceAlias
```

## 2. Start the DNS chain

```powershell
.\install.ps1
```

That copies a CA bundle, makes a local DoT cert if missing, and runs:

```powershell
docker compose up -d --force-recreate dnscrypt unbound pihole
```

Check:

```powershell
docker compose ps
docker exec unbound drill @127.0.0.1 dnssec.works
curl.exe -fsS http://127.0.0.1/admin/login
```

Admin UI: `http://127.0.0.1/admin/`

## 3. Point the LAN at Pi-hole

On the router: DHCP DNS = this PC’s `LAN_IPV4` only.

On this PC: set DNS to `127.0.0.1` so the box still resolves while Docker restarts.

## 4. Firewall (do not skip)

Allow DNS **only from your LAN**. Do not open 53 to the world.

```powershell
# Run in an elevated PowerShell. Replace the LAN CIDR.
New-NetFirewallRule -DisplayName "home-dns LAN TCP53" -Direction Inbound -Protocol TCP -LocalPort 53 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "home-dns LAN UDP53" -Direction Inbound -Protocol UDP -LocalPort 53 -RemoteAddress 192.168.1.0/24 -Action Allow
```

Do **not** bind DNS to `0.0.0.0` or `[::]`. Compose already publishes `${LAN_IPV4}:53` and admin on `127.0.0.1` only.

## 5. Recreate later

```powershell
.\install.ps1
```

## Notes

- **Geo-lock** (`scripts/geolock-apply.sh`) is Linux nftables. It is not used on Windows.
- Monitoring is optional: `docker compose --profile monitoring up -d`
- Tailscale DNS: set `TAILSCALE_IPV4` and `COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml`
- Same compose files as Linux. Do not add `1.1.1.1` to Pi-hole upstreams.
