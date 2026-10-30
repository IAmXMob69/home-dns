# GeoLock repository audit

Scope: the DNS geolock (`table inet geolock`) and the companion country/malice
nftables tables in this repository, compared read-only against one live host.
Nothing on the live host was changed, reloaded or restarted for this audit.
Placeholders: `<home>` = the operator's home directory, `<user>`/`<uid>` = the
desktop login, `<LAN>` = the private LAN range.

Line numbers refer to this branch unless marked `origin/main:`.

## 1. Architecture

| Piece | Where | What it does |
|---|---|---|
| Settings | `geolock/settings.env` (example: `geolock/settings.env.example:4-18`) | `GEOLOCK_ENABLED`, `GEOLOCK_MODE` (allow/deny), country lists, `GEOLOCK_PORTS`, `GEOLOCK_MAX_AGE_DAYS` |
| Bash builder | `scripts/geolock-apply.sh` | parse settings, fetch/caches lists, render `geolock.nft`, `nft -c`, atomic `nft -f` |
| Go port | `go/cmd/geolock-apply/main.go` | same behaviour; `scripts/geolock-apply.sh:9-11` execs `go/bin/geolock-apply` when present unless `PIHOLE_NO_GO=1` |
| CIDR policy (new) | `go/internal/cidr/cidr.go`, `lib/cidr.sh` | one strict validator, Go and Bash, shared fixture `tests/fixtures/cidr-cases.tsv` |
| Country tables | `automation/{india,africa,israel,saudi}-block/*.nft`, `automation/india-ca-block/` | static deny of whole countries / Indian CAs, IPv4 + IPv6 |
| Malice table | `scripts/malice-ip-apply.sh`, `go/cmd/malice-ip-apply` | FireHOL level1 into `inet malice_block` (IPv4) |
| Pi-hole side | `scripts/geolock-pihole.sh` | domain-level "Geo-Location Lock" group (not firewall) |
| Boot (live only) | `vaultos-country-block.service` | `nft -f` the country + malice files, then `ExecStartPost=-<home>/pihole/scripts/geolock-apply.sh` |

Data flow: ipverse `country/<cc>/ipv4-aggregated.txt` -> `fetch_cc`
(`scripts/geolock-apply.sh:97-115`, `main.go:221`) -> validated cache
`geolock/cache/<cc>.v4` -> re-validated (`scripts/geolock-apply.sh:128-136`,
`main.go:306-318`) -> rendered (`scripts/geolock-apply.sh:145-213`,
`main.go:129-190`) -> `nft -c` (via `unshare -rn` when not root,
`scripts/geolock-apply.sh:27-32`, `main.go:335-340`) -> `mv` into
`geolock/cache/geolock.nft` -> `nft -f` (`scripts/geolock-apply.sh:225`).
The file starts with `table; delete table; table {...}` so the swap is atomic.

Lists are only refreshed when older than `GEOLOCK_MAX_AGE_DAYS` (default 7,
`scripts/geolock-apply.sh:46,100`) or on `--refresh`; there is no timer, so in
practice refresh happens at boot.

## 2. CIDR validation

### Before (origin/main, identical in Go and Bash)

* `origin/main:scripts/geolock-apply.sh:102-104` and
  `origin/main:go/cmd/geolock-apply/main.go:33-34,204-208`: keep lines matching
  `^[0-9]`, then require `^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`.
* Accepted: octets > 255, prefix /33-/99, host bits, leading zeros, `/0`.
* Silently dropped: any line not starting with a digit (so a stray IPv6 or
  garbage line vanished without a warning). CRLF failed the whole list (safe).
* The cache was trusted on every later run; it was never re-checked.

What nft 1.1.7 does with those inputs (verified in a throwaway `unshare -rn`
namespace):

| Input | nft result | Impact |
|---|---|---|
| `010.0.0.0/8` | read as octal, becomes `8.0.0.0/8` | wrong network allowed/denied |
| `10.0.0.1/8` | silently masked to `10.0.0.0/8` | hides upstream data errors |
| `999.1.1.0/24` | nft tries a DNS lookup of the "hostname" | network I/O during load, confusing errors |
| `0.0.0.0/0` | accepted | allow mode: geolock becomes a no-op; deny mode: all DNS dropped |
| `/33`, `/129`, zones (`%eth0`) | rejected by nft | whole load fails (fail-safe but noisy) |
| `::ffff:1.2.3.0/120` | accepted | IPv4 data smuggled into an IPv6 set |
| duplicates / overlaps | merged by `auto-merge` | harmless |

### After (this branch)

Policy, documented at the top of `go/internal/cidr/cidr.go` and mirrored in
`lib/cidr.sh`:

* trim ASCII whitespace (so CRLF lists work); in lists skip blank lines and
  lines starting with `#`; inline comments are rejected;
* `ADDRESS/BITS` required, BITS decimal without leading zeros, 1..32 / 1..128
  (`/0` rejected);
* host bits must be zero (no silent masking);
* IPv4 octets 0-255 without leading zeros (no octal ambiguity);
* IPv6: hex in either case, `::` compression; rejects zones, embedded dotted
  IPv4, IPv4-mapped addresses and the wrong family;
* output is the trimmed input line unchanged, so valid upstream data renders
  byte-for-byte as before;
* a list with zero valid prefixes is an error ("no IPv4 prefixes").

Go uses `net/netip` (`cidr.go:63-110`) plus the extra textual checks; Bash is a
pure-builtin implementation (`lib/cidr.sh:32-112`, no subshells, glob matching
instead of `=~` for speed; a 30k-line US list takes about 7 s on the fallback
path).

## 3. nftables tables, sets and chains

| Table | Sets | Chains (priority) | Notes |
|---|---|---|---|
| `inet geolock` | `pass4` (127/8, 10/8, 172.16/12, 192.168/16, 100.64/10), `listed4` | input, forward, output | **IPv4 only**: `ip saddr`/`ip daddr` matches on `GEOLOCK_PORTS` (53,853). Forward uses `ct status dnat ... ct original proto-dst` to catch Docker-published DNS. Optional tailscaled underlay accept and an app cgroup rule (allow mode). |
| `inet india_block` | `in4`, `in6` (interval, auto-merge) | input, output, forward (-10) | `automation/india-block/india-block.nft:10054-10070`: all traffic to the country out/forwarded; DNS (53/853/8443) from it in, incl. Docker DNAT |
| `inet africa_block` | `in4`, `in6` | input, output, forward (-9) | `automation/africa-block/africa-block.nft:215-231`: all traffic to the country out/forwarded; DNS (53/853/8443) from it in, incl. Docker DNAT |
| `inet israel_block` | `in4`, `in6` | input, output, forward (-8) | `automation/israel-block/israel-block.nft:52-68`: all traffic to the country out/forwarded; DNS (53/853/8443) from it in, incl. Docker DNAT |
| `inet saudi_block` | `in4`, `in6` | input, output, forward (-7) | `automation/saudi-block/saudi-block.nft:40-56`: all traffic to the country out/forwarded; DNS (53/853/8443) from it in, incl. Docker DNAT |
| `inet india_ca_block` | `ca4`, `ca6` | input, output, forward (-7) | `automation/india-ca-block/india-ca-block.nft:34-49` |
| `inet malice_block` | IPv4 | generated | `scripts/malice-ip-apply.sh:31-45` (`ipaddress.ip_network(strict=False)`, i.e. it masks host bits by design; Go mirrors it at `go/cmd/malice-ip-apply/main.go:47-68`) |
| `inet dns_egress` | - | - | live only, mentioned at `README.md:161`, not in the repo |

## 4. Live vs repository (read-only comparison)

* **Generated ruleset matches.** Rendering the live settings + live cache with
  the repo code (old Bash, old Go, new Bash, new Go) gives a `geolock.nft` that
  is byte-identical (same sha256) to the live `geolock/cache/geolock.nft`.
* **Live script drift.** The live copies of `scripts/geolock-apply.sh` and
  `main.go` hard-code the tailscale underlay rule and a desktop-app cgroup
  (computed with `id -u <user>`). The repo expresses the same thing through
  `GEOLOCK_TAILSCALE_UNDERLAY=1` and `GEOLOCK_APP_CGROUP`, and with those set
  the output is identical. Recommend switching the live host to the env vars.
* **Country table drift.** The live `/etc/nftables.d` copies of the
  india/africa/israel/saudi tables add an `input` chain dropping
  `meta l4proto {tcp,udp} th dport {53,853,8443}` from `in4`/`in6`. The repo
  copies have no input chain.
* **Live-only units.** `vaultos-country-block.service` and
  `vaultos-dns-egress.service` (table `inet dns_egress`) are not in the repo;
  `nftables.service` is inactive.
* **Settings drift.** Live deny list omits PK/BD/LK/NP/BT/MV/AF that the example
  includes (`geolock/settings.env.example:15`); the example lacks
  `GEOLOCK_MAX_AGE_DAYS`.
* **Cache.** Live cache files were older than 7 days at audit time, so the next
  boot will try to download (with cache fallback). Orphan uppercase cache files
  (`DE.v4` etc.) from an older version are left behind.

## 5. Test coverage

Before: `go/cmd/geolock-apply/main_test.go` covered settings parsing, codes,
`Ruleset` and the old regex filter; CI ran the Bash builder + `nft -c` once.
No IPv6 tests, no Bash tests, no Go/Bash parity check.

After (this branch):

* `tests/fixtures/cidr-cases.tsv`: 78 shared IPv4/IPv6 accept/reject cases.
* `go/internal/cidr/cidr_test.go`: `TestValidateFixture`, `TestParseList`,
  `TestBashMirror` (same fixture through `lib/cidr.sh`), `TestBashMirrorFuzz`
  (3000 deterministic mutations, Go and Bash must agree), `TestBashFilterMirror`
  (whole-list output and exit code).
* `go/cmd/geolock-apply/main_test.go:61-92`: `TestFilterList` (header, CRLF,
  whitespace, bare IP, HTML, comments-only, host bits, `010.x`, `0/0`, IPv6) and
  `TestCheckCgroup`.
* CI (`.github/workflows/ci.yml:97-110`): builds the Go tool and requires the
  Bash and Go outputs to be identical (`cmp`) in allow and deny mode.

Still untested: the live boot unit, real `nft -f` load + rollback, IPv6 geolock
(does not exist yet).

## 6. Monitoring

`pihole-exporter` (Go and Python) exports Pi-hole/DNS metrics only. There are
no nftables counters, no "geolock loaded / list age / element count" metrics,
and nothing in Prometheus/Grafana shows firewall drops. A silently failed
geolock load at boot would go unnoticed.

## 7. Bugs, by severity

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Live boot unit runs a user-owned script and user-owned `go/bin` binary as root (local privilege escalation path), and the geolock step is `ExecStartPost=-...`, i.e. fail-open. | **Fix prepared** (`scripts/install-geolock-system.sh`, not applied): root-owned copy, no `-` |
| 2 | Medium | Leading-zero octets are read as octal by nft (`010.0.0.0/8` -> `8.0.0.0/8`). | **Fixed**, tested |
| 3 | Medium | `/0`, host bits, octets > 255, `/33`-`/99` accepted by the validator. | **Fixed**, tested |
| 4 | Medium | Cached lists never re-validated; a bad or old-format cache reached nft. | **Fixed**: every run re-validates, dies with "nothing changed" |
| 5 | Medium | Go continued after a cache read error and built a partial allow list (`origin/main:go/cmd/geolock-apply/main.go:309-312`); Bash aborted. | **Fixed**, Go now aborts like Bash |
| 6 | Medium | Geolock is IPv4 only although the table is `inet`; IPv6 on 53/853 is not geolocked. | **Switch added**: `GEOLOCK_IPV6=1` builds `listed6`/`pass6`; default 0 keeps the live ruleset byte-identical |
| 7 | Medium | Repo country tables lack the live inbound DNS `input` chains (drift). | Documented |
| 8 | Low | `999.x` style entries make nft do DNS lookups at load. | **Fixed** (rejected) |
| 9 | Low | `GEOLOCK_APP_CGROUP` was interpolated into the ruleset unchecked (quote injection, e.g. `a" accept comment "`); Bash stripped one leading `/`, Go all of them. | **Fixed**: validated in both, same trimming |
| 10 | Low | Non-digit lines silently dropped (e.g. IPv6 in a v4 list). | **Fixed**: now an error naming the line |
| 11 | Low | No refresh timer; staleness only handled at boot. | Recommendation |
| 12 | Low | No post-load verification or rollback. | **Fixed**: verify drop rules and set contents after load, else reload the previous table (Bash and Go) |
| 13 | Low | No firewall metrics. | **Added** `monitoring/nft-counters.py` (not deployed; `docs/nft-counters.md`) |
| 14 | Low | Country `forward` counters count reply packets, so inbound blocks are attributed to the wrong rule. | Documented |
| 15 | Low | Redundant `iifname/oifname tailscale0` forward rules (a catch-all drop follows). | Documented |
| 16 | Low | `dns_egress` table and `vaultos-*` units not in the repo. | Documented |
| 17 | Low | `settings.env.example` lacks `GEOLOCK_MAX_AGE_DAYS`; orphan uppercase cache files. | Example **fixed**; orphan files documented |
| 18 | Low | `GEOLOCK_PORTS` accepts out-of-range ports (caught later by `nft -c`). | Documented |

## 8. Verification of this branch

* Live config (live settings + live cache, offline URL, underlay + app cgroup
  env vars, dry run): old Bash, old Go, new Bash and new Go produce the same
  `geolock.nft`, byte-identical to the live file.
* Refresh path against a local ipverse mirror (70 countries), allow and deny:
  all cache files and `geolock.nft` identical across the four implementations.
* Negative: a downloaded `010.0.0.0/8` is refused (old code accepted it); a lax
  cache entry (`3.0.0.1/8`) is refused; the cgroup injection is refused.
* The rendered ruleset loads with `nft -f` inside `unshare -rn`; dry runs use
  `nft -c` in a user+net namespace. Nothing was loaded on the host.
* `go vet ./...`, `go test ./...`, `gofmt`, `shellcheck`, `ruff`, `yamllint`,
  `tests/test_exporter.py`, `tests/test_pihole_groups.py`: all pass.

## 9. Recommended plan for steps 3-5

**Step 3: Rust updater (fetch only).**
Fetch ipverse `ipv4-aggregated.txt` and `ipv6-aggregated.txt` per country,
validate with the same policy (port `cidr.go`, run it against
`tests/fixtures/cidr-cases.tsv` in `cargo test`), write `cache/<cc>.v4` and
`cache/<cc>.v6` atomically (tmp + fsync + rename), keep the previous good copy,
and print a dry-run diff (added/removed prefixes per country, with a size-change
guard). It writes files only; it never touches nft. Go/Bash keep re-validating.

**Step 4: Renderer + atomic load with rollback.**
Render separate `ip`/`ip6` sets (`listed4`, `listed6`, `pass6` for `::1`,
`fe80::/10`, `fc00::/7`) with independent input/forward/output rules per family,
behind a new `GEOLOCK_IPV6` switch that defaults off so today's ruleset stays
identical. Load with `nft -f`, then verify (table exists, element counts match,
DNS probe on 53/853), else reload the previous `geolock.nft`. Fail closed for
the geolock table only, never for the rest of the firewall.

**Step 5: Namespace first, then the host.**
Load the new ruleset in an `unshare -rn` / `ip netns` sandbox with a dummy
resolver and run allow/deny probes from synthetic source addresses per family.
Only then enable on the host, during a window, with the rollback file ready.

Alongside: move the boot unit to a root-owned binary under `/usr/local` (fixes
bug 1) and drop the `-` from the geolock `ExecStartPost` once rollback exists;
add an nft counters exporter (per-table drop counters, list age, element
counts) to Prometheus; add a weekly refresh timer; bring the live country-table
input chains and `dns_egress` into the repo.

## 10. Status of steps 3-6

**Step 3 (Rust updater): blocked.** No `rustc`, `cargo` or `rustup` on the
host, and installing the `rust` package needs root. Not started; the plan in
section 9 stands. Go and Bash already validate every list, so nothing depends on it.

**Step 4 (IPv4/IPv6 + rollback): done** on branch `geolock-ipv6`, Bash and Go.

* `GEOLOCK_IPV6` (default 0) adds `pass6` (`::1/128`, `fe80::/10`, `fc00::/7`)
  and `listed6`, and an `ip6` rule after every `ip` rule. Countries with no
  IPv6 list upstream (404, e.g. CF, ER) are logged and listed as empty; a 404
  never replaces a good cached list.
* `GEOLOCK_INBOUND` / `GEOLOCK_OUTBOUND` (default 1) switch the input+forward
  chains and the output chain independently.
* Load: snapshot the current table (checked with `nft -c`), load, then verify
  the number of drop rules per chain and the first element of each set. On any
  failure the previous table is reloaded and the run fails; with no previous
  table the new one is kept (never removes protection). `GEOLOCK_NFT` lets tests
  inject failures.
* With today's settings (IPv6 off) the output is byte-identical to the live
  `geolock.nft`; Bash and Go agree on every combination (allow/deny, IPv6 on/off,
  each direction).

**Step 5 (namespace first): harness added**, `tests/netns/geolock-netns.sh`.
It builds a server and a client namespace joined by a veth pair (documentation
prefixes only), runs a small DNS responder on both sides, and checks queries
from listed and unlisted sources, inbound and outbound, IPv4 and IPv6, UDP and
TCP, for each implementation, plus rollback on an injected load failure and on
an injected verify failure. Runs unprivileged with `unshare -rn`; CI runs it
with `sudo unshare -n`.

Boot fix: `scripts/install-geolock-system.sh` (preview with `--dry-run`, undo
with `--rollback`). It refuses to install unless the new root-owned copy
renders the live ruleset byte-for-byte. See `docs/geolock-boot.md`.

**Step 6 (monitoring): exporter added, not deployed.** See `docs/nft-counters.md`.
