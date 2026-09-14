# Windows setup (plain English)

This is the long version of the README. You are installing home DNS on **one Windows PC** that stays on at home.

## What you need

- Windows 10 or 11
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Git for Windows](https://git-scm.com/download/win) (for the `git clone` command)
- A password you will remember (this becomes your Pi-hole login)

You do **not** need a GitHub account or a Docker account.

## Step 1 — Install Docker Desktop

1. Download Docker Desktop and install it.
2. Reboot if it asks.
3. Open **Docker Desktop** and wait until it says it is running (green / “Engine running”).
4. If it nags you to **Sign in**, click the skip / continue without account option. This project does not need a Docker login.

## Step 2 — Download this project

Right-click the Start button → **Terminal** or **Windows PowerShell**.

```powershell
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
copy .env.example .env
notepad .env
```

## Step 3 — Fill in three things in Notepad

| Line | What to type | Example |
|------|----------------|---------|
| `FTLCONF_webserver_api_password=` | **Your Pi-hole login password** | a long phrase you will not forget |
| `LAN_IPV4=` | This PC’s home IP | often `192.168.1.50` style, **not** `0.0.0.0` |
| `LAN_GATEWAY=` | Your router’s IP | often `192.168.1.1` |
| `LAN_CIDR=` | Your house network | often `192.168.1.0/24` |

Find this PC’s IP: Settings → Network → your Wi‑Fi or Ethernet → Properties → **IPv4 address**.  
Or in PowerShell:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '127.*' } |
  Format-Table IPAddress, InterfaceAlias
```

Use the `192.168…` or `10…` address. Save Notepad. Close it.

## Step 4 — Start it

```powershell
.\install.ps1
```

If Windows blocks the script, run this once, then try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

The first run downloads images and can take several minutes. Docker Desktop must stay open.

## Step 5 — Sign into Pi-hole (the main login)

On **this same PC**, open Edge or Chrome:

**http://127.0.0.1/admin/**

- There is **no username**.
- Password = the `FTLCONF_webserver_api_password` line from `.env`.
- If it fails, Docker Desktop is not running, or `.\install.ps1` did not finish.

That page is where you see blocked ads and change lists.

## Step 6 — Tell the house to use this PC for DNS

On your **router** (often by typing `192.168.1.1` in a browser):

1. Sign in with the router / ISP password (that is the **router**, not Pi-hole).
2. Find DHCP or DNS settings.
3. Set DNS to this PC’s `LAN_IPV4` only.
4. Save. Toggle Wi‑Fi on phones if they still use the old DNS.

On **this Windows PC**, set DNS to `127.0.0.1` (Adapter settings → IPv4 → Use the following DNS → `127.0.0.1`).

## Step 7 — Windows Firewall

Only your house should use this DNS. Open PowerShell **as Administrator**:

```powershell
New-NetFirewallRule -DisplayName "home-dns LAN TCP53" -Direction Inbound -Protocol TCP -LocalPort 53 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "home-dns LAN UDP53" -Direction Inbound -Protocol UDP -LocalPort 53 -RemoteAddress 192.168.1.0/24 -Action Allow
```

Change `192.168.1.0/24` if your house uses `10.x`. Do not make a rule for “Any” remote address on port 53.

## Optional logins (skip unless you want them)

### Grafana (pretty graphs)

```powershell
docker compose --profile monitoring up -d
```

Sign in at **http://127.0.0.1:3000**

- Username: `admin`
- Password: `GRAFANA_ADMIN_PASSWORD` from `.env`

### Tailscale (Pi-hole from your phone)

1. Install Tailscale on this PC and your phone.
2. Sign in at **https://login.tailscale.com** (Google / Microsoft / GitHub / email). Same account on both.
3. In PowerShell: `tailscale ip -4` — put that in `.env` as `TAILSCALE_IPV4`.
4. Set `COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml` in `.env`.
5. Run `.\install.ps1` again.
6. On the phone, open the Tailscale URL for this PC. That page is still **Pi-hole** — use the **Pi-hole password**.

### Geo-lock

Not available on Windows (it uses Linux firewall tools). Use the Windows Firewall rules above instead.

## Things that do **not** have a login

- **Unbound** and **dnscrypt** — background only.
- **GitHub** — you only copied files.
- **Docker Desktop** — skip “Sign in” if it asks.

## Don’t

- Don’t add `1.1.1.1` inside Pi-hole’s DNS server list.
- Don’t port-forward 53/80/443 on the router to this PC.
- Don’t copy `.env` or `unbound\tls.key` into git.

## Start it again later

Start Docker Desktop, then:

```powershell
cd home-dns
.\install.ps1
```
