#!/usr/bin/env python3
"""Pi-hole Prometheus exporter (ChristopherAlphonse/pihole), adapted for v6 auth + volume DB."""
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import requests

PIHOLE_HOST = os.getenv("PIHOLE_HOSTNAME", "pihole")
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "80")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")
PIHOLE_PROTOCOL = os.getenv("PIHOLE_PROTOCOL", "http")
EXPORTER_PORT = int(os.getenv("EXPORTER_PORT", "9617"))
FTL_DB_PATH = os.getenv("FTL_DB_PATH", "/etc/pihole/pihole-FTL.db")
CACHE_TTL = 30
TOP_N = 20

# FTL query_status values that mean "blocked" (src/enums.h). Regex and
# CNAME-chain blocks matter here: Geo-Location Lock is regex-based.
BLOCKED_STATUS_IDS = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)
BLOCKED_STATUS_NAMES = {
    "GRAVITY", "REGEX", "DENYLIST",
    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
    "EXTERNAL_BLOCKED_EDE15",
    "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
    "DBBUSY", "SPECIAL_DOMAIN",
}
CACHED_STATUS_IDS = (3, 17)

metrics_cache = {}
per_client_metrics = {}
top_domains = []
top_clients = []
query_types = {}
upstream_servers = {}
top_permitted_domains = []
top_blocked_domains = []
pihole_up = 0.0
session = requests.Session()
# What a failed Pi-hole call can raise: network/HTTP errors and bad JSON shapes.
API_ERRORS = (requests.RequestException, ValueError, KeyError, TypeError, AttributeError)


def api_base():
    return f"{PIHOLE_PROTOCOL}://{PIHOLE_HOST}:{PIHOLE_PORT}"


def login():
    if not PIHOLE_PASSWORD:
        return
    try:
        r = session.post(f"{api_base()}/api/auth", json={"password": PIHOLE_PASSWORD}, timeout=10)
        data = r.json() if r.content else {}
        sid = data.get("session", {}).get("sid")
        csrf = data.get("session", {}).get("csrf", "")
        if sid:
            session.headers["X-FTL-SID"] = sid
            if csrf:
                session.headers["X-FTL-CSRF"] = csrf
            print("Authenticated to Pi-hole v6 API")
        else:
            print(f"Pi-hole auth failed: HTTP {r.status_code}")
    except API_ERRORS as e:
        print(f"Pi-hole auth error: {e}")


def api_get(path):
    url = f"{api_base()}{path}"
    r = session.get(url, timeout=10)
    if r.status_code in (401, 403):
        login()
        r = session.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def sqlite_scalar(query, default=0.0):
    try:
        con = sqlite3.connect(f"file:{FTL_DB_PATH}?mode=ro", uri=True, timeout=5)
        row = con.execute(query).fetchone()
        con.close()
        return float(row[0] if row and row[0] is not None else default)
    except (sqlite3.Error, ValueError, TypeError) as e:
        print(f"sqlite: {e}")
        return default


def fetch_pihole_stats():
    global metrics_cache, per_client_metrics, top_domains, top_clients
    global query_types, upstream_servers, top_permitted_domains, top_blocked_domains, pihole_up
    try:
        data = api_get("/api/stats/summary")
        queries = data.get("queries", {})
        clients_data = data.get("clients", {})
        gravity = data.get("gravity", {})
        metrics_cache = {
            "dns_queries_total": float(queries.get("total", 0)),
            "dns_blocked_total": float(queries.get("blocked", 0)),
            "dns_forwarded_total": float(queries.get("forwarded", 0)),
            "dns_cached_total": float(queries.get("cached", 0)),
            "clients_total": float(clients_data.get("total", 0)),
            "devices_total": float(clients_data.get("total", 0)),
            "devices_active_24h": float(clients_data.get("active", 0)),
            "dns_queries_24h": float(queries.get("total", 0)),
            "dns_blocked_24h": float(queries.get("blocked", 0)),
            "dns_forwarded_24h": float(queries.get("forwarded", 0)),
            "dns_cached_24h": float(queries.get("cached", 0)),
            "clients_24h": float(clients_data.get("active", 0)),
            "gravity_domains": float(gravity.get("domains_being_blocked", 0)),
        }
        query_types = {k: float(v) for k, v in (queries.get("types") or {}).items()}
        pihole_up = 1.0
    except API_ERRORS as e:
        print(f"API summary failed, using sqlite fallback: {e}")
        pihole_up = 0.0
        since = "timestamp >= CAST(strftime('%s','now') AS INTEGER) - 86400"
        blocked_ids = ",".join(str(x) for x in BLOCKED_STATUS_IDS)
        cached_ids = ",".join(str(x) for x in CACHED_STATUS_IDS)
        total = sqlite_scalar(f"SELECT COUNT(*) FROM query_storage WHERE {since}")
        blocked = sqlite_scalar(f"SELECT COUNT(*) FROM query_storage WHERE {since} AND status IN ({blocked_ids})")
        forwarded = sqlite_scalar(f"SELECT COUNT(*) FROM query_storage WHERE {since} AND status=2")
        cached = sqlite_scalar(f"SELECT COUNT(*) FROM query_storage WHERE {since} AND status IN ({cached_ids})")
        clients = sqlite_scalar(f"SELECT COUNT(DISTINCT client) FROM query_storage WHERE {since}")
        metrics_cache = {
            "dns_queries_total": total,
            "dns_blocked_total": blocked,
            "dns_forwarded_total": forwarded,
            "dns_cached_total": cached,
            "clients_total": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "devices_total": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "devices_active_24h": clients,
            "dns_queries_24h": total,
            "dns_blocked_24h": blocked,
            "dns_forwarded_24h": forwarded,
            "dns_cached_24h": cached,
            "clients_24h": clients,
            "gravity_domains": sqlite_scalar("SELECT value FROM counters WHERE id=0", 0),
        }

    try:
        data = api_get(f"/api/stats/top_domains?count={TOP_N}")
        top_domains = []
        top_permitted_domains = []
        for item in data.get("domains", []):
            rec = {"domain": item.get("domain", "unknown"), "queries": float(item.get("count", 0)), "blocked": 0.0}
            top_domains.append(rec)
            top_permitted_domains.append({"domain": rec["domain"], "queries": rec["queries"]})
    except API_ERRORS as e:
        print(f"top domains: {e}")
        top_domains, top_permitted_domains = [], []

    try:
        data = api_get("/api/stats/top_clients")
        per_client_metrics, top_clients = {}, []
        for item in data.get("clients", []):
            ip = item.get("ip", "unknown")
            count = float(item.get("count", 0))
            per_client_metrics[ip] = {"queries": count, "blocked": 0.0, "cached": 0.0, "forwarded": 0.0}
            top_clients.append({"mac": "", "name": item.get("name") or ip, "ip": ip, "queries": count})
    except API_ERRORS as e:
        print(f"top clients: {e}")
        per_client_metrics, top_clients = {}, []

    try:
        data = api_get("/api/stats/upstreams")
        upstream_servers = {u.get("name") or u.get("ip", "unknown"): float(u.get("count", 0)) for u in data.get("upstreams", [])}
    except API_ERRORS as e:
        print(f"upstreams: {e}")
        upstream_servers = {}

    try:
        # FTL counts every blocked status here (gravity, regex, deny, CNAME, ...).
        data = api_get(f"/api/stats/top_domains?blocked=true&count={TOP_N}")
        top_blocked_domains = [
            {"domain": item.get("domain", "unknown"), "queries": float(item.get("count", 0))}
            for item in data.get("domains", [])
        ]
    except API_ERRORS as e:
        print(f"top blocked domains: {e}; sampling recent queries")
        top_blocked_domains = sample_blocked_queries()
    return True


def is_blocked_status(status):
    if isinstance(status, int):
        return status in BLOCKED_STATUS_IDS
    return str(status or "").upper() in BLOCKED_STATUS_NAMES


def sample_blocked_queries():
    try:
        data = api_get("/api/queries?length=500")
    except API_ERRORS as e:
        print(f"blocked sample: {e}")
        return []
    blocked = {}
    for q in data.get("queries", []):
        if is_blocked_status(q.get("status")):
            d = q.get("domain", "unknown")
            blocked[d] = blocked.get(d, 0) + 1
    top = sorted(blocked.items(), key=lambda x: -x[1])[:TOP_N]
    return [{"domain": d, "queries": float(c)} for d, c in top]


def escape_label_value(value):
    if value is None:
        return "unknown"
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def gauge(lines, name, help_text, value):
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name} {value}")


def labeled(lines, name, help_text, label, items):
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    for key, value in items:
        lines.append(f'{name}{{{label}="{escape_label_value(key)}"}} {value}')


def format_metrics():
    m = metrics_cache
    lines = []
    gauge(lines, "pihole_up", "1 if the Pi-hole API answered the last scrape", pihole_up)
    # Pi-hole v6 summary values cover the last 24 hours, so they are gauges.
    gauge(lines, "pihole_dns_queries_total", "DNS queries (last 24h)", m.get("dns_queries_total", 0))
    gauge(lines, "pihole_dns_blocked_total", "Blocked DNS queries (last 24h)", m.get("dns_blocked_total", 0))
    gauge(lines, "pihole_dns_forwarded_total", "Forwarded DNS queries (last 24h)", m.get("dns_forwarded_total", 0))
    gauge(lines, "pihole_dns_cached_total", "Cached DNS queries (last 24h)", m.get("dns_cached_total", 0))
    gauge(lines, "pihole_dns_queries_24h", "DNS queries in the last 24 hours", m.get("dns_queries_24h", 0))
    gauge(lines, "pihole_dns_blocked_24h", "Blocked DNS queries in the last 24 hours", m.get("dns_blocked_24h", 0))
    gauge(lines, "pihole_dns_forwarded_24h", "Forwarded DNS queries in the last 24 hours", m.get("dns_forwarded_24h", 0))
    gauge(lines, "pihole_dns_cached_24h", "Cached DNS queries in the last 24 hours", m.get("dns_cached_24h", 0))
    gauge(lines, "pihole_clients_total", "Total unique clients", m.get("clients_total", 0))
    gauge(lines, "pihole_clients_24h", "Unique clients in last 24 hours", m.get("clients_24h", 0))
    gauge(lines, "pihole_gravity_domains", "Total domains in gravity blocklist", m.get("gravity_domains", 0))
    labeled(lines, "pihole_client_queries_total", "DNS queries per client", "client",
            ((c, s["queries"]) for c, s in per_client_metrics.items()))
    labeled(lines, "pihole_query_type_total", "DNS queries by type", "type", query_types.items())
    labeled(lines, "pihole_upstream_queries_total", "Queries forwarded to upstream servers", "server",
            upstream_servers.items())
    labeled(lines, "pihole_top_permitted_domains_total", "Top permitted domains", "domain",
            ((i["domain"], i["queries"]) for i in top_permitted_domains[:TOP_N]))
    labeled(lines, "pihole_top_blocked_domains_total", "Top blocked domains (gravity, regex, deny)", "domain",
            ((i["domain"], i["queries"]) for i in top_blocked_domains[:TOP_N]))
    return "\n".join(lines) + "\n"


EXTRA_MAX = 4 << 20


def extra_metrics():
    """EXTRA_METRICS_FILE contents (e.g. from monitoring/nft-counters.py), or ""."""
    path = os.getenv("EXTRA_METRICS_FILE", "")
    if not path:
        return ""
    try:
        with open(path) as f:
            text = f.read(EXTRA_MAX + 1)
    except OSError:
        return ""
    if not text or len(text) > EXTRA_MAX:
        return ""
    return text if text.endswith("\n") else text + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = (format_metrics() + extra_metrics()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        return


def background_fetcher():
    while True:
        fetch_pihole_stats()
        time.sleep(CACHE_TTL)


if __name__ == "__main__":
    print(f"Starting Pi-hole exporter on {EXPORTER_PORT}")
    login()
    fetch_pihole_stats()
    Thread(target=background_fetcher, daemon=True).start()
    HTTPServer(("0.0.0.0", EXPORTER_PORT), MetricsHandler).serve_forever()
