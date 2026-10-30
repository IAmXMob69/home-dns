#!/usr/bin/env python3
"""Run the exporter against a mocked Pi-hole v6 API and check /metrics.

Every metric the Grafana dashboard queries must be present, and regex/CNAME
blocks must show up in the blocked-domain series.
"""
import importlib.util
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
SID = "test-sid"
STATE = {"blocked_endpoint": True}

SUMMARY = {
    "queries": {"total": 1000, "blocked": 250, "forwarded": 500, "cached": 250,
                "types": {"A": 600, "AAAA": 300, "HTTPS": 100}},
    "clients": {"active": 7, "total": 9},
    "gravity": {"domains_being_blocked": 123456},
}
TOP_PERMITTED = {"domains": [{"domain": "example.com", "count": 40}, {"domain": "wikipedia.org", "count": 9}]}
TOP_BLOCKED = {"domains": [{"domain": "ads.example", "count": 30}, {"domain": "shop.example.in", "count": 12}]}
QUERIES = {"queries": [
    {"domain": "ads.example", "status": "GRAVITY"},
    {"domain": "shop.example.in", "status": "REGEX"},
    {"domain": "cdn.example.in", "status": "REGEX_CNAME"},
    {"domain": "tracker.example", "status": "DENYLIST"},
    {"domain": "example.com", "status": "FORWARDED"},
    {"domain": "example.com", "status": "CACHE"},
]}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/auth" and body.get("password") == "pw":
            return self.reply(200, {"session": {"valid": True, "sid": SID, "csrf": "c"}})
        return self.reply(401, {"session": {"valid": False}})

    def do_GET(self):
        if self.headers.get("X-FTL-SID") != SID:
            return self.reply(401, {"error": {"key": "unauthorized"}})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/stats/summary":
            return self.reply(200, SUMMARY)
        if u.path == "/api/stats/top_domains":
            if q.get("blocked") == ["true"]:
                if not STATE["blocked_endpoint"]:
                    return self.reply(500, {})
                return self.reply(200, TOP_BLOCKED)
            return self.reply(200, TOP_PERMITTED)
        if u.path == "/api/stats/top_clients":
            return self.reply(200, {"clients": [{"ip": "10.0.0.5", "name": "pc", "count": 50}]})
        if u.path == "/api/stats/upstreams":
            return self.reply(200, {"upstreams": [{"ip": "172.30.90.3", "name": "unbound", "count": 500}]})
        if u.path == "/api/queries":
            return self.reply(200, QUERIES)
        return self.reply(404, {})


def load_exporter(path, port):
    import os
    os.environ.update(PIHOLE_HOSTNAME="127.0.0.1", PIHOLE_PORT=str(port), PIHOLE_PASSWORD="pw",
                      FTL_DB_PATH="/nonexistent/pihole-FTL.db")
    spec = importlib.util.spec_from_file_location(f"exp_{abs(hash(path))}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dashboard_metrics():
    d = json.loads((ROOT / "monitoring/grafana/dashboards/pihole-dashboard.json").read_text())
    names = set()

    def walk(panels):
        for p in panels:
            for t in p.get("targets", []):
                names.update(re.findall(r"\bpihole_[a-z0-9_]+", t.get("expr", "")))
            walk(p.get("panels", []))

    walk(d["panels"])
    return names


def series(text):
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, val = line.rsplit(" ", 1)
            out[key] = float(val)
    return out


def check(path):
    srv = HTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    exp = load_exporter(path, srv.server_address[1])
    problems = []

    exp.login()
    exp.fetch_pihole_stats()
    text = exp.format_metrics()
    s = series(text)
    names = {k.split("{")[0] for k in s}
    for m in sorted(dashboard_metrics()):
        if m not in names:
            problems.append(f"dashboard metric {m} missing")
    if s.get("pihole_dns_queries_24h") != 1000.0:
        problems.append("pihole_dns_queries_24h != 1000")
    if 'pihole_top_blocked_domains_total{domain="shop.example.in"}' not in s:
        problems.append("regex-blocked domain missing from top blocked (API path)")

    STATE["blocked_endpoint"] = False
    exp.fetch_pihole_stats()
    s = series(exp.format_metrics())
    for d in ("shop.example.in", "cdn.example.in", "tracker.example", "ads.example"):
        if f'pihole_top_blocked_domains_total{{domain="{d}"}}' not in s:
            problems.append(f"{d} missing from sampled blocked domains (fallback path)")
    if 'pihole_top_blocked_domains_total{domain="example.com"}' in s:
        problems.append("permitted domain counted as blocked")
    STATE["blocked_endpoint"] = True

    try:
        from prometheus_client.parser import text_string_to_metric_families
        list(text_string_to_metric_families(text))
    except ImportError:
        pass
    # EXTRA_METRICS_FILE (nft counters) is appended to /metrics when set.
    if hasattr(exp, "extra_metrics"):
        import os
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            prom = os.path.join(d, "nft.prom")
            subprocess.run([sys.executable, str(ROOT / "monitoring/nft-counters.py"), "--input",
                            str(ROOT / "tests/fixtures/nft-ruleset.json"), "--output", prom], check=True)
            os.environ["EXTRA_METRICS_FILE"] = prom
            combined = exp.format_metrics() + exp.extra_metrics()
            os.environ["EXTRA_METRICS_FILE"] = os.path.join(d, "missing.prom")
            if exp.extra_metrics() != "":
                problems.append("missing EXTRA_METRICS_FILE should add nothing")
            del os.environ["EXTRA_METRICS_FILE"]
        if 'home_dns_nft_drop_packets_total{family="inet",table="geolock"' not in combined:
            problems.append("nft counters missing from combined /metrics")
        try:
            from prometheus_client.parser import text_string_to_metric_families
            list(text_string_to_metric_families(combined))
        except ImportError:
            pass

    srv.shutdown()
    return problems


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "monitoring/pihole-exporter.py")
    problems = check(target)
    for p in problems:
        print(f"FAIL: {p}")
    print("exporter test:", "FAIL" if problems else "OK")
    sys.exit(1 if problems else 0)
