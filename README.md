# Home DNS

One computer runs ad-blocking DNS for your whole house.

Phones, TVs and laptops ask this computer where a website lives. Pi-hole blocks ads
and trackers. The rest of the chain looks up the real answer privately.

## What runs

- **Pi-hole 2026.10.0**: the blocker and the admin page at https://127.0.0.1/admin/ (HTTP redirects to HTTPS).
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

5. Open https://127.0.0.1/admin/ on this computer (accept the local certificate once). There is no username; type the password from step 3.
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
  IPv4 only by default. Set `GEOLOCK_IPV6=1` to filter IPv6 too; otherwise allow mode leaves IPv6 unfiltered.
  `GEOLOCK_INBOUND` and `GEOLOCK_OUTBOUND` turn each direction on or off on its own.
  After loading, the script checks the live table matches the file. If loading or that check fails, it restores the previous table.
  Test it without touching the host firewall: `unshare -rn tests/netns/geolock-netns.sh`.
  Boot install (root-owned copy, failure is not ignored): see [docs/geolock-boot.md](docs/geolock-boot.md).
- **Country-block zones**: `sudo nft -f automation/<name>-block/<name>-block.nft` for `africa`, `india`, `israel` or `saudi`.
  They stop this PC and its containers from connecting out to that region (all traffic, not just DNS).
- **Malicious IPs**: `sudo ./scripts/malice-ip-apply.sh` drops the FireHOL level1 list. Never blocks your LAN or Tailscale.
- **Privacy shield**: `./scripts/privacy-shield-pihole.sh` blocks telemetry and analytics. Toggle it in Pi-hole: Groups → Data collection halt.

Do not add `1.1.1.1` to Pi-hole's upstream servers; that skips the blocker. Do not open port 53 to the internet.

## Indian CA lockout

Three independent layers stop this host from trusting or reaching eMudhra (emSign) and the other certificate authorities licensed under CCA India, including the CCA root itself. Each works on its own; use all three for full coverage.

- **Certificates**: `./scripts/distrust-india-cas.sh` moves the four emSign roots, the only Indian roots in the stores distributions ship, onto the system distrust list (Arch, Fedora, Debian/Ubuntu) and verifies the result. Roots are matched by label and pinned SHA-256 fingerprint, so nothing else is touched. `--check` reports without changing anything. Needs sudo.
- **DNS**: the CA entries in `privacy-shield/privacy-shield.tsv` block each CA's site, OCSP, CRL, repository and eSign names. When a CA sits inside a larger organisation (Sify, C-DAC, Protean, CSC, CDSL, Jio, NIC), only its CA hosts are listed and the parent domain keeps working. Load them with `./scripts/privacy-shield-pihole.sh`.
- **Firewall (Linux)**: `sudo nft -f automation/india-ca-block/india-ca-block.nft` drops traffic to and from address space that a CA owns and announces from its own ASN (eMudhra, (n)Code Solutions, IDRBT). CAs hosted on ISP, data-centre, cloud or CDN ranges are covered by the DNS layer only, so no unrelated services are caught.
  To load it at every boot, install the rule and its unit, then enable the unit:

  ```sh
  sudo install -Dm644 automation/india-ca-block/india-ca-block.nft /etc/nftables.d/india-ca-block.nft
  sudo install -Dm644 automation/india-ca-block/india-ca-block.service /etc/systemd/system/india-ca-block.service
  sudo systemctl daemon-reload && sudo systemctl enable --now india-ca-block.service
  ```

  The unit loads only its own table, so it leaves the rest of the ruleset alone and works without the stock `nftables` service.

Sites and documents that rely on these CAs will show certificate or signature errors afterwards, which is expected. Undo with `sudo nft delete table inet india_ca_block`, by removing the files the script placed in the blocklist directory (or the `!mozilla/emSign*` lines in `/etc/ca-certificates.conf`) and rerunning `update-ca-trust` or `update-ca-certificates`, and by disabling the entries in Pi-hole.


## Admin TLS and resolver integrity

"Encrypt the Pi-hole" here means three concrete things. It does **not** mean handing
lookups to Cloudflare, Google or Quad9 over DoH — that would trade a self-hosted
path for a third-party view of every query. The chain stays:

device → Pi-hole → Unbound (DNSSEC) → dnscrypt-proxy (anonymized DNSCrypt) → internet.

### What was already strong

- Unbound validates DNSSEC (`auto-trust-anchor-file` / `root.key`). Bogus zones
  such as `fail01.dnssec.works` return SERVFAIL. Pi-hole itself has DNSSEC
  checking off on purpose so answers are not double-validated into false SERVFAILs.
- Hardening flags on: `harden-glue`, `harden-dnssec-stripped`, `harden-below-nxdomain`,
  `harden-large-queries`, `harden-short-bufsize`, `deny-any`, `qname-minimisation`
  (strict), `aggressive-nsec`, `prefetch-key`, `val-clean-additional`.
- Left off on purpose: `harden-algo-downgrade` (breaks `.top` while that zone
  publishes a stale DS) and `use-caps-for-id` (0x20 casing breaks some authoritative
  servers).
- Admin already spoke HTTPS on loopback with a self-signed RSA-4096 cert. TLS 1.0/1.1
  were refused. dnsdist terminates DoT/DoH for clients separately.

### What this repo adds

1. **Admin TLS lock-down** in `docker-compose.yml` (alongside container hardening:
   digest-pinned images, `no-new-privileges` / `pids_limit` where safe, Pi-hole
   container DNS pointed at Unbound on `172.30.90.4`, destructive API off):
   - `FTLCONF_webserver_port=80or,443os` — HTTP redirects to HTTPS when the cert is present.
   - `FTLCONF_webserver_tls_validity=0` — FTL will not overwrite a custom cert.
   - `FTLCONF_webserver_advancedOpts` — `ssl_protocol_version=4` (TLS 1.2+) and an
     AEAD-only `ssl_cipher_list` for the mbedTLS build inside FTL. Weak CBC/SHA-1
     suites (for example `ECDHE-RSA-AES128-SHA`) are no longer offered.
2. **Cert generator**: `scripts/harden-pihole-tls.sh` writes an ECDSA P-384
   (or RSA-4096) cert into `etc-pihole/tls.pem`. Pass extra names at generate time;
   nothing Tailscale-specific is committed:

```bash
ADMIN_TLS_DNS=your-host.your-tailnet.ts.net \
ADMIN_TLS_IP=127.0.0.1,${LAN_IPV4},${TAILSCALE_IPV4} \
./scripts/harden-pihole-tls.sh
```

3. **Unbound**: `val-clean-additional: yes` and clearer comments around the
   intentional tradeoffs above. No change to the dnscrypt-proxy upstream.

### Applying compose changes (do not blind-copy)

The `docker-compose.yml` in this repo is the shared source of truth, including
admin TLS lock-down, image digest pins, `no-new-privileges`, `pids_limit`, and
container DNS pointed at Unbound. A running checkout may also carry local-only
host firewall rules (for example an `inet dns_egress` nftables table) that are
**not** in this file.

**Do not** `cp` this file over a live stack. That overwrites any local hardening
you have not merged back yet. Instead:

1. `git pull` in the checkout that runs the stack (or copy only the files you
   mean to update — never assume compose is the only one that drifted).
2. If your live `docker-compose.yml` has diverged, merge by hand: keep the
   `FTLCONF_webserver_*` TLS lines from this repo and keep any stronger local
   service hardening you still need, then replace the live file with the
   reconciled result.
3. Recreate only after reviewing the diff:

```bash
diff -u /path/to/live/docker-compose.yml ./docker-compose.yml
docker compose up -d pihole unbound
```

The cert script only writes `etc-pihole/tls.pem` (and prints the TLS settings).
It does not touch `docker-compose.yml`.

### Threat model (honest)

| Risk | Mitigation |
|------|------------|
| Someone on the LAN sniffs the admin password | HTTPS + redirect; admin ACL stays loopback / Docker / Tailscale Serve |
| Downgrade to TLS 1.0 or a CBC suite | `ssl_protocol_version=4` + AEAD cipher list |
| Forged / stripped DNS answers | Unbound DNSSEC validation + harden-* flags |
| ISP or Wi-Fi sees plaintext queries | dnscrypt-proxy via anonymizing relays (already in place) |
| Third party builds a query log about you | Kept off the table: no DoH/DoT to Cloudflare/Google/Quad9 as upstream |

This is current best practice for a self-hosted blocker. It is not a claim about
any agency's capability.

### Attempt tripwire (optional)

A read-only monitor that records when a device still tries to look up one of the blocked certificate-authority domains, so you can tell whether anything on the network is attempting to reach them. It is a logging tripwire, not an attack tool: it only reads Pi-hole's query database, writes to a local log, and sends nothing to anyone.

- `scripts/ca-tripwire.py` reads Pi-hole's long-term query database (`pihole-FTL.db`) read-only, matches the certificate-authority deny rules from `privacy-shield/privacy-shield.tsv`, and appends one line per new attempt to `$HOME/.local/share/ca-tripwire/hits.log`. Each line is tab-separated: ISO-8601 time, client IP, client hostname (or `-`), domain. A cursor file beside the log keeps its place, so each attempt is recorded once. The first run only notes where it is and watches from there, so installing it does not replay old history.
- The log is the interface. A desktop notifier tails that file and raises the alerts; the watcher itself never notifies.
- It reaches the database through the `pihole` container (`docker exec`, no root). Override `CA_TRIPWIRE_CONTAINER` / `CA_TRIPWIRE_DB`, or set `CA_TRIPWIRE_FTL_DB` to read a host-side database directly, if your setup differs.

Run it on a timer with systemd user units (no root):

```sh
cp automation/ca-tripwire/ca-tripwire.service automation/ca-tripwire/ca-tripwire.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ca-tripwire.timer
```

The units expect the checkout at `~/home-dns`; adjust the `ExecStart` path if yours differs. Test it:

```sh
dig @127.0.0.1 emsign.com
# wait for Pi-hole to flush the query to its long-term database (up to a minute), then:
systemctl --user start ca-tripwire.service
cat "$HOME/.local/share/ca-tripwire/hits.log"
```

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
