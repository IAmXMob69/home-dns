# Linux setup (plain English)

This is the long version of the README. You are installing home DNS on **one Linux computer** that stays on at home.

## What you need

- A Linux PC that can stay on
- Docker (the program that runs Pi-hole)
- About 15 minutes
- A password you will remember (this becomes your Pi-hole login)

You do **not** need a GitHub account, a Docker account, or anyone else’s passwords.

## Step 1 — Install Docker

Install Docker for your Linux flavor, then log out and back in (or reboot) so your user can run it.

Check:

```bash
docker version
```

If that prints a version, you are fine.

## Step 2 — Download this project

Open Terminal:

```bash
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
cp .env.example .env
nano .env
```

(`nano` is a simple text editor. Ctrl+O saves. Ctrl+X quits.)

## Step 3 — Fill in three things in `.env`

| Line | What to type | Example |
|------|----------------|---------|
| `FTLCONF_webserver_api_password=` | **Your Pi-hole login password** | a long phrase you will not forget |
| `LAN_IPV4=` | This computer’s home IP | often `192.168.1.50` style, **not** `0.0.0.0` |
| `LAN_GATEWAY=` | Your router’s IP | often `192.168.1.1` |
| `LAN_CIDR=` | Your house network | often `192.168.1.0/24` |

Find this PC’s IP:

```bash
hostname -I
```

Use the address that looks like `192.168.x.x` (or `10.x.x.x`). Not `127.0.0.1`.

Save the file.

## Step 4 — Start it

```bash
./install.sh
```

Wait until it finishes. The first run downloads images and can take a few minutes.

## Step 5 — Sign into Pi-hole (the main login)

On **this same computer**, open Firefox or Chrome:

**http://127.0.0.1/admin/**

- There is **no username**.
- Password = the `FTLCONF_webserver_api_password` value from `.env`.
- If the page does not load, `./install.sh` did not finish or Docker is not running.

That page is where you see blocked ads, add lists, and change Pi-hole settings.

Do **not** use `http://pi.hole` unless you know it points at `127.0.0.1`. Use the `127.0.0.1` address.

## Step 6 — Tell the house to use this computer for DNS

On your **router** (usually by typing `192.168.1.1` in a browser — that is the router’s own login, not Pi-hole):

1. Sign in with the router sticker / ISP password (that is the **router**, not Pi-hole).
2. Find DHCP / DNS / LAN settings.
3. Set DNS to **this PC’s `LAN_IPV4` only**.
4. Save. Phones may need Wi‑Fi toggled off and on.

On **this Linux PC**, set its own DNS to `127.0.0.1` so it still works if Docker is restarting.

## Step 7 — Lock the door (firewall)

Only devices in your house should use this DNS.

```bash
sudo ufw allow from 192.168.1.0/24 to any port 53 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 53 proto udp
```

Change `192.168.1.0/24` if your house uses `10.x`.  
Never run `sudo ufw allow 53` with no “from” — that invites the whole internet.

## Optional logins (skip unless you want them)

### Grafana (pretty graphs)

Not started unless you ask for it.

```bash
docker compose --profile monitoring up -d
```

Sign in at **http://127.0.0.1:3000**

- Username: `admin`
- Password: `GRAFANA_ADMIN_PASSWORD` from `.env`

### Tailscale (open Pi-hole from your phone when you are not home)

1. Install Tailscale on this PC and on your phone.
2. Sign in at **https://login.tailscale.com** with Google, Microsoft, GitHub, or email. Same account on both devices.
3. On this PC:

```bash
tailscale ip -4
```

Put that number in `.env` as `TAILSCALE_IPV4`. Set:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml
```

Then:

```bash
sudo tailscale set --accept-dns=false
sudo tailscale serve --bg http://127.0.0.1:80
```

4. On your phone (on Tailscale), open the `https://….ts.net/admin/` link Tailscale shows.
5. That page is **still Pi-hole**. Use the **Pi-hole password**, not your Tailscale password.

### Geo-lock (block or allow countries)

Linux only. No website login.

```bash
cp geolock/settings.env.example geolock/settings.env
nano geolock/settings.env   # set GEOLOCK_ENABLED=1
sudo ./scripts/geolock-apply.sh
```

Your house LAN is always allowed so you cannot lock yourself out.

## Things that do **not** have a login

- **Unbound** — checks DNS answers. No page.
- **dnscrypt** — encrypts lookups. No page.
- **GitHub** — you only downloaded files.
- **Docker** — it runs the boxes. You can skip creating a Docker Hub user.

## Don’t

- Don’t add `1.1.1.1` as a Pi-hole upstream. Ads will sneak around the blocker.
- Don’t port-forward 53, 80, or 443 on the router to this PC.
- Don’t commit `.env` or `unbound/tls.key` to git.

## Start it again later

```bash
cd home-dns
./install.sh
```
