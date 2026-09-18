# Home DNS

This turns one computer into ad-blocking DNS for your house.

Phones, TVs, and laptops ask this computer “where is that website?”  
Pi-hole blocks ads. Unbound and dnscrypt fetch the real answers privately.

You do **not** sign into GitHub or Docker to use this.  
You **do** pick a Pi-hole password and type it in a web page. That is the main login.

## Linux (one computer on your home network)

1. Install [Docker](https://docs.docker.com/engine/install/).
2. Open Terminal and run:

```bash
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
cp .env.example .env
nano .env
```

3. In that file, set a **Pi-hole password** (`FTLCONF_webserver_api_password`) and this PC’s **home IP** (`LAN_IPV4`). Save. Exit.
4. Run:

```bash
./install.sh
```

5. Sign into Pi-hole: on **this same computer**, open a browser to  
   **http://127.0.0.1/admin/**  
   Username is not used. Type the password from step 3.

Full walkthrough: [SETUP.md](./SETUP.md)

## Windows (one computer on your home network)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and start it. Wait until it says it is running. You do **not** need a Docker account.
2. Open PowerShell and run:

```powershell
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
copy .env.example .env
notepad .env
```

3. Same as Linux: set the **Pi-hole password** and this PC’s **home IP**. Save. Close Notepad.
4. Run:

```powershell
.\install.ps1
```

5. Sign into Pi-hole: on **this same computer**, open a browser to  
   **http://127.0.0.1/admin/**  
   Type the password you put in `.env`.

Full walkthrough: [SETUP-windows.md](./SETUP-windows.md)

## How you sign in (each piece)

| Thing | Do you sign in? | How |
|------|------------------|-----|
| **GitHub** (download) | No | Public clone. No account needed. |
| **Docker** | No | Just install and start it. Skip “Sign in” if it asks. |
| **Pi-hole** (ad blocker page) | **Yes — this is the one that matters** | Browser: http://127.0.0.1/admin/ — password from `.env` (`FTLCONF_webserver_api_password`). |
| **Unbound** | No | Works in the background. |
| **dnscrypt** | No | Works in the background. |
| **Grafana** (graphs, optional) | Yes, only if you turn graphs on | Browser: http://127.0.0.1:3000 — user `admin` — password from `.env` (`GRAFANA_ADMIN_PASSWORD`). |
| **Tailscale** (see the page from your phone, optional) | Yes, only if you install Tailscale | App or https://login.tailscale.com — Google / Microsoft / GitHub / email. Then open the Pi-hole link Tailscale gives you. Still use the **Pi-hole** password on that page. |
| **Geo-lock** (optional) | No | In Pi-hole: **Group management → Groups → Geo-Location Lock** (on/off). Extra Linux firewall: `sudo ./scripts/geolock-apply.sh`. |
| **Data collection halt** | No | In Pi-hole: **Group management → Groups → Data collection halt**. Extra Linux IP drop: `sudo ./scripts/malice-ip-apply.sh`. |

## Geo-Location Lock (in Pi-hole)

This is a switch **inside Pi-hole**, not a GitHub setting.

```bash
./scripts/geolock-pihole.sh
```

Then http://127.0.0.1/admin/ → sign in with the Pi-hole password → **Group management** → **Groups** → **Geo-Location Lock** on or off.

On = US-centric lock: Africa (every African ccTLD, including Nigeria), India, rest of South Asia, Malaysia, Israel, Saudi. Off = those names work. Do not delete the list; use the switch.

Do not put `1.1.1.1` into Pi-hole’s DNS servers. That skips the blocker.

Do not open port 53 to the whole internet.


## Data collection halt (in Pi-hole)

Blocks telemetry and tracker names (Mozilla, Microsoft, analytics, crash reporters).

```bash
./scripts/privacy-shield-pihole.sh
```

Then http://127.0.0.1/admin/ → **Group management** → **Groups** → **Data collection halt**.

Known-bad IPs (FireHOL level1), Linux only:

```bash
sudo ./scripts/malice-ip-apply.sh
```

## License

Configs are as-is for personal reuse. Pi-hole, Unbound, and dnscrypt-proxy keep their own licenses.
