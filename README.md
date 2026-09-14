# Home DNS stack

Reproducible **Pi-hole + Unbound + dnscrypt-proxy** (Docker Compose), with optional Prometheus/Grafana and Tailscale Serve for the admin UI.

Secrets, live gravity DB, private keys, and host identifiers are **not** included — use `.env.example` and `scripts/gen-dot-cert.sh`.

```bash
git clone https://github.com/IAmXMob69/home-dns.git
cd home-dns
cp .env.example .env   # set LAN_IPV4 and passwords
./install.sh
```

## Quick path

```
LAN clients → Pi-hole (block) → Unbound (DNSSEC / DoT) → dnscrypt-proxy (anonymized) → internet
```

**Full install:** see [SETUP.md](./SETUP.md).

## Layout

| Path | What |
|------|------|
| `docker-compose.yml` | dnscrypt, unbound, pihole, optional monitoring |
| `docker-compose.tailscale.yml` | overlay for Tailscale host records |
| `dnscrypt/dnscrypt-proxy.toml` | anonymized upstream resolvers |
| `unbound/custom.conf.d/hardening.conf` | access-control, qname-min, forward to dnscrypt |
| `monitoring/` | exporter + Prometheus + Grafana provisioning |
| `.env.example` | all required env vars (copy to `.env`) |
| `scripts/gen-dot-cert.sh` | local DoT certificate |
| `install.sh` | CA bundle + cert + `docker compose up` |
| `geolock/` | optional country gate (off until `settings.env` + `sudo ./scripts/geolock-apply.sh`) |

## Security

- Admin UI binds to loopback only; use Tailscale Serve (or SSH tunnel) for remote access.
- DNS publishes on your LAN IPv4 only — never wholesale `0.0.0.0`/`[::]` on a dual-stack host.
- Do not commit `.env`, `unbound/tls.key`, or `etc-pihole/` runtime data.

## License

Configs here are provided as-is for personal reuse. Pi-hole, Unbound, and dnscrypt-proxy remain under their own licenses.
