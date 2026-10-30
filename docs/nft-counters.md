# nftables drop counters in Prometheus

`monitoring/nft-counters.py` reads `nft -j list ruleset` and writes one series
per counted drop rule:

```
home_dns_nft_drop_packets_total{family="inet",table="india_block",chain="input",rule="drop India IPv4 DNS in"} 12
home_dns_nft_drop_bytes_total{family="inet",table="geolock",chain="input",rule="meta_l4proto_tcp_udp_th_dport_53_853_ip_saddr_not_listed4"} 840
home_dns_nft_counters_up 1
home_dns_nft_counters_timestamp_seconds 1793330000
```

How each rule is named:

* A rule with a comment is named by the comment. The country tables all have one.
* A rule without a comment is named by its matches. The geolock rules don't
  have comments, because adding them would change the live ruleset.
* Rule handles are not used, because they change on every reload.

Use `--tables` to export only some tables. Use `--all` to include counted
rules that aren't drop rules.

`nft` needs root, so a small root timer writes a text file and the existing
`pihole-exporter` serves it. The exporter reads `EXTRA_METRICS_FILE` (Go and
Python versions) and adds it to `/metrics`. If the variable is unset or the file
is missing, the output doesn't change.

## Deploy (not done on the host yet)

```bash
sudo install -D -m 0755 monitoring/nft-counters.py /usr/local/lib/home-dns/nft-counters.py
sudo install -m 0644 systemd/system/home-dns-nft-counters.service systemd/system/home-dns-nft-counters.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now home-dns-nft-counters.timer
cat /var/lib/home-dns/metrics/nft.prom

docker compose -f docker-compose.yml -f monitoring/docker-compose.nft-counters.yml \
  --profile monitoring up -d pihole-exporter
curl -s 127.0.0.1:9617/metrics | grep home_dns_nft_
```

The service only has `CAP_NET_ADMIN`, with a read-only system except for
`/var/lib/home-dns`, and runs every 30 s. Example queries:

```promql
sum by (table) (rate(home_dns_nft_drop_packets_total[5m]))
time() - home_dns_nft_counters_timestamp_seconds > 120     # exporter stalled
```

To remove it, disable the timer, delete the two unit files and
`/var/lib/home-dns/metrics`, and drop the compose overlay.

## Tests

* `tests/test_nft_counters.py` runs against a saved ruleset
  (`tests/fixtures/nft-ruleset.json`).
* `tests/test_exporter.py` checks the combined `/metrics` output.
* The netns harness checks that real drops show up in the export.
