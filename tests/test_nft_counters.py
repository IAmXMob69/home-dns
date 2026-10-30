#!/usr/bin/env python3
"""Check monitoring/nft-counters.py against a saved `nft -j list ruleset` dump.

The fixture was taken from a throwaway network namespace with a geolock table
(allow ZZ, IPv6 on) and a country-block style table; counters were then set to
known values.
"""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "nft-ruleset.json"

spec = importlib.util.spec_from_file_location("nft_counters", ROOT / "monitoring" / "nft-counters.py")
nc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nc)


def main():
    data = json.loads(FIXTURE.read_text())
    s = nc.drop_counters(data)
    got = {(lab["table"], lab["chain"], lab["rule"]): (p, b) for lab, p, b in s}
    want_rules = {
        ("geolock", "input", "meta_l4proto_tcp_udp_th_dport_53_853_ip_saddr_not_listed4"),
        ("geolock", "input", "meta_l4proto_tcp_udp_th_dport_53_853_ip6_saddr_not_listed6"),
        ("geolock", "output", "meta_l4proto_tcp_udp_th_dport_53_853_ip_daddr_not_listed4"),
        ("example_block", "input", "drop Example IPv4 DNS in"),
        ("example_block", "output", "drop IPv6 Example"),
    }
    missing = want_rules - got.keys()
    assert not missing, missing
    assert len(s) == 10, len(s)  # 6 geolock drops + 4 country drops; "not a drop" is skipped
    assert all(lab["family"] == "inet" for lab, _, _ in s)
    assert got[("example_block", "input", "drop Example IPv4 DNS in")][1] == \
        100 * got[("example_block", "input", "drop Example IPv4 DNS in")][0]

    assert len(nc.drop_counters(data, all_rules=True)) == 11
    assert {lab["table"] for lab, _, _ in nc.drop_counters(data, table_re="geolock")} == {"geolock"}

    text = nc.render(s, now=1700000000)
    assert "home_dns_nft_counters_up 1\n" in text
    assert "home_dns_nft_counters_timestamp_seconds 1700000000\n" in text
    assert "# TYPE home_dns_nft_drop_packets_total counter\n" in text
    assert ('home_dns_nft_drop_bytes_total{family="inet",table="example_block",chain="output",'
            'rule="drop IPv6 Example"} ') in text
    # Same name twice in one chain gets a suffix, never a duplicate series.
    dup = {"nftables": [{"rule": {"family": "inet", "table": "t", "chain": "c", "comment": "x",
                                  "expr": [{"counter": {"packets": 1, "bytes": 2}}, {"drop": None}]}}] * 2}
    assert [lab["rule"] for lab, _, _ in nc.drop_counters(dup)] == ["x", "x #2"]
    assert 'rule="a\\"b"' in nc.render([({"rule": 'a"b'}, 1, 1)])

    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "nft.prom")
        assert nc.main(["--input", str(FIXTURE), "--output", out]) == 0
        assert oct(os.stat(out).st_mode & 0o777) == "0o644"
        assert "drop Example IPv6 DNS in" in Path(out).read_text()
        assert nc.main(["--input", os.path.join(d, "missing.json"), "--output", out]) == 1
        assert "home_dns_nft_counters_up 0\n" in Path(out).read_text()
        assert [f for f in os.listdir(d) if f.startswith(".")] == []
    print("nft-counters: ok")


if __name__ == "__main__":
    sys.exit(main())
