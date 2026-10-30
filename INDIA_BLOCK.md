# India block

Four layers, each independent. Every one has its own undo and none of them touches
the geolock, the other country tables or `dns_egress`.

| Layer | What it blocks | Where | Needs root |
|---|---|---|---|
| `.in` regex | every `.in` name | `geolock/pihole/regex.txt` | no |
| IDN TLD regex | India's 15 IDN TLDs (`.भारत` and the others) | `geolock/pihole/india-lang-regex.txt` | no |
| `indic-idn-guard` | names written in Indian scripts under any TLD | `go/cmd/indic-idn-guard` | no |
| India inbound firewall | every new inbound connection from Indian IP space, IPv4 and IPv6, all ports, host and Docker | `automation/india-inbound/` | yes |

Outbound traffic to Indian IP space is the separate `india_block` zone
(`automation/india-block/india-block.nft`).

## IDN TLD regex

India's internationalized TLDs come from the IANA root zone database: every TLD whose
sponsor is the National Internet Exchange of India. The file lists each one with its
script. `.இலங்கை` (`xn--xkc2al3hye2a`) is Sri Lanka's and is left out.

```sh
./scripts/india-lang-pihole.sh --dry-run   # show what would be added
./scripts/india-lang-pihole.sh             # add it (skips entries already present)
```

CI checks that this list and the one built into `indic-idn-guard` stay identical.

## indic-idn-guard

Pi-hole only ever sees the punycode form of a name (`xn--p1b6ci4b4b3a.com` for
`उदाहरण.com`), so a regex cannot tell which script it is written in. `indic-idn-guard`
reads the names Pi-hole answered in the last 15 minutes from its long-term query
database (read-only), decodes each `xn--` label with `golang.org/x/net/idna`, and adds
an exact deny entry for every name with a label in:

Devanagari (plus Extended and Extended-A), Bengali/Assamese, Gurmukhi, Gujarati, Oriya,
Tamil, Telugu, Kannada, Malayalam, Ol Chiki, Meetei Mayek (plus Extensions) and the
Vedic Extensions block.

It only adds deny entries commented `india-lang indic-idn-guard`. It never deletes
anything and never touches allow lists, regex entries, groups or `gravity.db` directly.
Names are converted to ASCII and validated before they reach the Pi-hole CLI, which
runs without a shell. `--max` (default 200) caps one run; `--dry-run` changes nothing.

```sh
make -C go bin/indic-idn-guard
go/bin/indic-idn-guard --dry-run --window 24h
cp systemd/user/pihole-indic-idn-guard.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now pihole-indic-idn-guard.timer
```

The timer runs it every 2 minutes. It needs Pi-hole's long-term database
(`database.DBinterval`, default 60 s), so a new name is denied within about 3 minutes
of its first lookup.

## India inbound firewall

`automation/india-inbound/india-inbound-block.nft` is its own table, `inet
india_inbound`. It drops every new inbound connection from Indian IPv4 and IPv6 space
on the host and on the forward path to Docker containers. Loopback, private LAN
ranges, Docker bridges and Tailscale are always allowed, and replies to connections
you start are not affected.

```sh
sudo automation/india-inbound/apply.sh
```

The script backs up the current tables, checks the rule with `nft -c`, installs it with
a boot unit (`vaultos-india-inbound.service`), confirms no other table changed and that
DNS still answers, and rolls itself back if any step fails. Drops are logged (rate
limited) with the prefixes `INDIA-IN DROP` and `INDIA-FWD DROP`:
`journalctl -k -g INDIA-`.

## Limits

- **Only names, never content.** DNS sees which name is looked up, not the language of
  the page, message or video behind it. HTTPS content cannot be read without breaking
  the encryption of every device, which this repo will not do.
- **Arabic script is not blocked.** Urdu, Kashmiri and Sindhi share it with dozens of
  other countries. Only India's own Arabic-script TLDs are blocked.
- **Latin letters are not blocked.** Hindi or any other Indian language typed in Latin
  letters (`namaste.com`) looks like any other name.
- **Scripts cross borders.** Bengali is also Bangladesh's script and Tamil is also used
  in Sri Lanka and Singapore, so names in those scripts from there are blocked too.
- **First lookup gets through.** `indic-idn-guard` reacts to queries, so the first
  lookup of a new Indian-script name is answered before the deny entry exists.
- **Location is not identity.** Scammers use VPNs and servers outside India; the IP
  layer only stops traffic that comes from Indian address space.

## Undo

- IDN TLD regex: Pi-hole admin → Domains, delete the entry commented
  `india-lang IDN TLDs`.
- indic-idn-guard: `systemctl --user disable --now pihole-indic-idn-guard.timer`, then
  delete the entries commented `india-lang indic-idn-guard` (or
  `pihole deny remove <name>`).
- India inbound firewall: `sudo systemctl disable --now vaultos-india-inbound.service`
  (its stop step deletes the table), then
  `sudo rm /etc/nftables.d/india-inbound-block.nft /etc/systemd/system/vaultos-india-inbound.service`.
