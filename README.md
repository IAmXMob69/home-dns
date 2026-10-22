# Home DNS

One computer runs ad-blocking DNS for your whole house.

Phones, TVs and laptops ask this computer where a website lives. Pi-hole blocks ads
and trackers. The rest of the chain looks up the real answer privately.

## What runs

- **Pi-hole 2026.10.0**: the blocker and the admin page at http://127.0.0.1/admin/.
- **Unbound**: checks answers (DNSSEC). It is Pi-hole's only upstream.
- **dnscrypt-proxy**: sends lookups out encrypted through anonymizing relays.
- **dnsdist**: encrypted DNS for your devices. DoT on port 853, DoH on port 8443 (`/dns-query`).
- **Prometheus + Grafana** (optional): graphs, fed by a small Go exporter.

The path is: device → Pi-hole → Unbound → dnscrypt-proxy → internet.
Ports only listen on 127.0.0.1, your LAN IP and (if you add it) your Tailscale IP. Never on the whole internet.

## Quick start (Linux)

1. Install [Docker](https://docs.docker.com/engine/install/).
2. Get the code and make your settings file:

```bash
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
cp .env.example .env
nano .env
```

3. Set at least `FTLCONF_webserver_api_password` (your Pi-hole password) and `LAN_IPV4` (this PC's home IP). Save.
4. Start it:

```bash
./install.sh
```

5. Open http://127.0.0.1/admin/ on this computer. There is no username; type the password from step 3.
6. Point your router's DNS (or each device) at `LAN_IPV4`.

Step-by-step guide: [SETUP.md](./SETUP.md). Windows: [SETUP-windows.md](./SETUP-windows.md) (Docker Desktop, then `.\install.ps1`).

Graphs: `docker compose --profile monitoring up -d`, then http://127.0.0.1:3000 (user `admin`, password `GRAFANA_ADMIN_PASSWORD`).

## Settings (.env)

Copy `.env.example` to `.env`. Never commit `.env`. A value that still says `your-...`, `change-me` or `x.x` counts as not set,
and any tool that needs it stops and tells you which one to fill in.

Stack:

- `FTLCONF_webserver_api_password`: Pi-hole admin password.
- `GRAFANA_ADMIN_PASSWORD`: Grafana password (graphs only).
- `TZ`: time zone for the containers.
- `LAN_IPV4`: this PC's fixed home IP. DNS listens here.
- `LAN_IPV6`: optional IPv6 address to listen on. Leave empty to skip.
- `TAILSCALE_IPV4`: this PC's Tailscale IP, for the Tailscale add-on file.
- `COMPOSE_FILE`: add `:docker-compose.tailscale.yml` to also listen on Tailscale.

Host tools (Linux scripts below):

- `LAN_CIDR`: your home network, like `192.168.1.0/24`. Firewall rules allow only this.
- `LAN_GATEWAY`: your router's IP. Used when `expose-lan` pins a fixed IP.
- `LAN_IPV6_CIDR`: optional IPv6 network to allow. Empty means IPv4 only.
- `WIFI_CON`, `WIFI_DEV`: the NetworkManager connection and device this PC uses. Find them with `nmcli -t -f NAME,DEVICE connection show --active`.
- `DOT_AUTH_NAME`: the name on the DoT certificate, like `your-host.your-tailnet.ts.net`. Or set `PIHOLE_DNS` directly.
- `PIHOLE_USER`: the login that owns the checkout. Defaults to whoever ran `sudo`.
- `TS_OPERATOR`: who may run `tailscale` without sudo. Defaults to you.
- `TS_HOSTNAME`: optional Tailscale name. Empty keeps the computer's name.
- `PIHOLE_WATCHDOG_LAN`: optional LAN IP the watchdog also checks. Defaults to `LAN_IPV4`.
- `IMPORT_LISTS_FILE`: adlist file for `import-lists`. Defaults to `pihole-automation/lists.txt`.
- `PIHOLE_ENV_FILE`: read settings from another file instead of `.env`.
- `PIHOLE_NO_GO=1`: run the shell or Python version instead of the Go build.

## Blocking extras

All optional. Each one only touches its own entries, and `--dry-run` previews where offered.

- **Geo-Location Lock (Pi-hole group)**: `./scripts/geolock-pihole.sh`. Blocks domains for Africa, India, South Asia, Malaysia, Israel and Saudi.
  Turn it on or off in Pi-hole: Group management → Groups → Geo-Location Lock.
- **Geolock firewall (Linux)**: `cp geolock/settings.env.example geolock/settings.env`, set `GEOLOCK_ENABLED=1`, then `sudo ./scripts/geolock-apply.sh`.
  Allow mode (the default) drops DNS traffic from every country not in `GEOLOCK_ALLOW_COUNTRIES`. Deny mode drops only `GEOLOCK_DENY_COUNTRIES`.
  Your LAN, loopback and Tailscale are always allowed.
- **Country-block zones**: `sudo nft -f automation/<name>-block/<name>-block.nft` for `africa`, `india`, `israel` or `saudi`.
  They stop this PC and its containers from connecting out to that region (all traffic, not just DNS).
- **Malicious IPs**: `sudo ./scripts/malice-ip-apply.sh` drops the FireHOL level1 list. Never blocks your LAN or Tailscale.
- **Privacy shield**: `./scripts/privacy-shield-pihole.sh` blocks telemetry and analytics. Toggle it in Pi-hole: Groups → Data collection halt.

Do not add `1.1.1.1` to Pi-hole's upstream servers; that skips the blocker. Do not open port 53 to the internet.

## Encrypted DNS and Tailscale

`install.sh` gives dnsdist a self-signed `pihole.lan` certificate. On a Tailscale node, get a real one:

```bash
DOT_AUTH_NAME=your-host.your-tailnet.ts.net ./scripts/refresh-dot-cert.sh
```

To reach Pi-hole from your phone away from home:

1. `sudo ./setup-tailscale-privileged.sh`: installs Tailscale, firewall rules and the boot-time unit.
2. `./join-tailnet.sh`: joins your tailnet without using Tailscale's DNS (that would loop).
3. `./publish-tailscale-dns.sh`: saves your Tailscale IP to `.env` and turns on `docker-compose.tailscale.yml`.

The country-block zones and `GEOLOCK_TAILSCALE_UNDERLAY=1` let the `tailscaled` service through, so Tailscale can still find its relays.
That rule needs `tailscaled` running. If you do not use Tailscale, delete the `socket cgroupv2 ... tailscaled.service` line from the zone file first.

## Go tools

Every script runs its Go build from `go/bin/<tool>` when it exists, and its own shell or Python body when not.
Build them with `make -C go` (needs Go 1.26+). `PIHOLE_NO_GO=1` forces the old version for one run.

Setup and repair:

- `pihole-install` (`install.sh`): certificates, then start the DNS chain.
- `apply-stack`: start the stack, load lists, check DNS, then point this PC at it.
- `fix-pihole`: safe restart that only switches this PC to Pi-hole once it answers.
- `harden`: firewall so DNS and admin pages answer only this PC, your LAN and Tailscale.
- `expose-lan`: give this PC a fixed LAN IP and allow DNS from the LAN only.
- `rollback-dns`: put this PC back on Cloudflare and Google DNS. Pi-hole files are not touched.

Tailscale:

- `setup-tailscale-privileged`, `join-tailnet`, `publish-tailscale-dns`: see above.
- `refresh-dot-cert` (`scripts/refresh-dot-cert.sh`): renew the DoT/DoH certificate.

Firewall and lists:

- `geolock-apply`, `malice-ip-apply`: the Linux firewall extras above.
- `pihole-groups` (`scripts/lib/pihole_groups.py`): shared group sync for geolock and privacy shield.
- `install-privacy-shield` (`automation/`): load the privacy-shield deny rules.
- `import-lists`, `import-webpwnized-lists` (`automation/import-lists.*`): add adlists from a list file.
- `update-gravity` (`automation/`): refresh Pi-hole's blocklists.

Upkeep and checks:

- `watchdog` (`watchdog.py`): if Pi-hole stops answering, restart it once, then switch this PC to Cloudflare; switch back when it recovers.
- `healthcheck` (`automation/`): check containers, lists, Unbound and disk; notify on problems.
- `status` (`automation/`): print a short health report.
- `dns-probe` (`dns-probe.py`): send one test lookup (plain, DoT or DoH).
- `update-pihole` (`automation/`): pull new images; DNS fails over to Cloudflare during the swap.
- `backup`: save Pi-hole settings to `backups/` (keeps 3).
- `cleanup`: delete old list copies, debug logs and extra backups.
- `debug-window-off` (`automation/`): end a temporary debug logging window.
- `pihole-exporter` (`monitoring/pihole-exporter.py`): metrics for Grafana. Docker builds it from `go/`.

## Timers (systemd)

`systemd/user/` has timers for the watchdog (every 30 s), healthcheck (hourly), gravity (daily), cleanup (daily),
backup, image updates and the certificate (weekly). They expect the checkout at `~/home-dns`.
`systemd/system/pihole-tailscale-dns.service` republishes Tailscale DNS at boot. Install steps: [systemd/README.md](./systemd/README.md).

## Rollback

- This PC's DNS: `sudo ./rollback-dns.sh`.
- One tool back to shell or Python: `PIHOLE_NO_GO=1 ./<script>`. All of them: `make -C go clean`.
- Geolock firewall: set `GEOLOCK_ENABLED=0` in `geolock/settings.env` and run `sudo ./scripts/geolock-apply.sh` again.
- A country zone: `sudo nft delete table inet <name>_block` (for example `africa_block`).
- Malicious-IP list: `sudo nft delete table inet malice_block`, and remove its file from `/etc/nftables.d` so it stays off after reboot.
- Pi-hole groups: switch them off in Group management → Groups.
- Whole stack: `docker compose down`.

## License

Configs are as-is for personal reuse. Pi-hole, Unbound, dnscrypt-proxy and dnsdist keep their own licenses.
