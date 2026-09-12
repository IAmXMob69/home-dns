# Home DNS stack

Pi-hole + Unbound + dnscrypt-proxy on Docker Compose.

This is a **sanitized** write-up of how I run LAN DNS. No passwords, API keys, Tailscale IPs, exact host binds, or other private details. Copy ideas, not secrets.

## Path

```
LAN clients → Pi-hole (block) → Unbound (DNSSEC / local DoT) → dnscrypt-proxy (anonymized DNS) → internet
```

Unbound is **not** published on the LAN for plain DNS. Only Pi-hole serves port `53` on the LAN. Unbound DoT (`853`) is bound to loopback and the LAN address only — never `0.0.0.0` or `[::]`. This machine has a global IPv6 address, so a wildcard bind would be an open resolver waiting to happen.

## Pi-hole

- Image: `pihole/pihole` (v6 FTL)
- Upstream: **Unbound only** (no public resolvers in FTL — those would leak ads past the chain)
- DNSSEC in FTL: **off** (Unbound already validates; double-validation caused false SERVFAILs)
- Blocking mode: `NULL`, with EDNS blocking code enabled
- Cache size: `10000`
- Rate limit: `1000` queries / `60s` (tightened after a noisy client)
- Query logging on, ~30 days of local history (on-box only)
- Admin UI: **loopback only** (`127.0.0.1:80/443`). Remote access is through Tailscale Serve, not a WAN port forward
- Listening mode inside Docker is `ALL` so LAN clients work; **host publish rules + firewall** are what keep it from being world-open
- Container NTP: off

## Blocklists

Roughly **45 enabled lists** (gravity on the order of ~12M domains). Mix of StevenBlack, OISD small, Firebog-style ads / malware / tracking lists, plus a few allow and deny overrides for things that break in real use.

Notes from living with it:

- CNAME deep-inspect is **off** here — it was breaking legit Facebook graph / gateway CNAME chains
- Keep a small allowlist for the stuff you actually use; a huge gravity list without overrides is miserable

## Unbound

- Image: `klutchell/unbound`
- QNAME minimization on
- Default-deny access-control; allow loopback, Docker nets, and the home LAN `/24`
- Forwards to dnscrypt-proxy on the Compose network (not straight to `1.1.1.1` from FTL)
- LAN DNS-over-TLS for Private DNS clients on `853` with a **local** cert (not pasted here)

## dnscrypt-proxy

- Image: `klutchell/dnscrypt-proxy`
- **Not** published to the LAN — Unbound is the only client
- `require_dnssec` / `require_nolog` / `require_nofilter`
- Anonymized DNS routes enabled
- Small public resolver set (Cloudflare / Quad9 / dns.sb / dnscrypt.ca / Control D / Mullvad-style DoH, and similar)

## Monitoring (optional)

Prometheus + Grafana + a Pi-hole exporter, all bound to `127.0.0.1` only. Grafana signup and anonymous auth off. Nice to have; not required for DNS.

## Hardening habits that matter

1. Never bind DNS or the admin UI to `0.0.0.0` / `[::]` on a dual-stack host.
2. Keep public upstreams out of Pi-hole’s FTL config so ads can’t bypass Unbound.
3. Put the web UI behind loopback + a mesh VPN (Tailscale Serve), not port forwarding.
4. Cap Docker `json-file` log size so the box doesn’t fill itself.
5. Rate-limit aggressive clients before they look like an open resolver from the outside world’s point of view.

## What this repo is not

- Not my live `docker-compose.yml`
- Not my `.env`, TLS keys, or admin password
- Not a turnkey install script

If you build your own, start from official images, bind only the addresses you mean to, and treat every password and API token as local-only.

