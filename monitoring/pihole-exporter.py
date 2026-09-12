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

metrics_cache = {}
per_client_metrics = {}
top_domains = []
top_clients = []
query_types = {}
upstream_servers = {}
top_permitted_domains = []
top_blocked_domains = []
session = requests.Session()


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
    except Exception as e:
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
    except Exception as e:
        print(f"sqlite: {e}")
        return default


def fetch_pihole_stats():
    global metrics_cache, per_client_metrics, top_domains, top_clients
    global query_types, upstream_servers, top_permitted_domains, top_blocked_domains
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
    except Exception as e:
        print(f"API summary failed, using sqlite fallback: {e}")
        metrics_cache = {
            "dns_queries_total": sqlite_scalar("SELECT COUNT(*) FROM query_storage"),
            "dns_blocked_total": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status IN (1,4,5,6,7,8,9,10,11,15,16)"),
            "dns_forwarded_total": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status=2"),
            "dns_cached_total": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status=3"),
            "clients_total": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "devices_total": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "devices_active_24h": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "dns_queries_24h": sqlite_scalar("SELECT COUNT(*) FROM query_storage"),
            "dns_blocked_24h": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status IN (1,4,5,6,7,8,9,10,11,15,16)"),
            "dns_forwarded_24h": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status=2"),
            "dns_cached_24h": sqlite_scalar("SELECT COUNT(*) FROM query_storage WHERE status=3"),
            "clients_24h": sqlite_scalar("SELECT COUNT(*) FROM client_by_id"),
            "gravity_domains": sqlite_scalar("SELECT value FROM counters WHERE id=0", 0),
        }

    try:
        data = api_get("/api/stats/top_domains")
        top_domains = []
        top_permitted_domains = []
        for item in data.get("domains", []):
            rec = {"domain": item.get("domain", "unknown"), "queries": float(item.get("count", 0)), "blocked": 0.0}
            top_domains.append(rec)
            top_permitted_domains.append({"domain": rec["domain"], "queries": rec["queries"]})
    except Exception as e:
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
    except Exception as e:
        print(f"top clients: {e}")
        per_client_metrics, top_clients = {}, []

    try:
        data = api_get("/api/stats/upstreams")
        upstream_servers = {u.get("name") or u.get("ip", "unknown"): float(u.get("count", 0)) for u in data.get("upstreams", [])}
    except Exception as e:
        print(f"upstreams: {e}")
        upstream_servers = {}

    try:
        data = api_get("/api/queries?length=200")
        blocked = {}
        for q in data.get("queries", []):
            status = str(q.get("status", ""))
            if any(x in status.upper() for x in ("GRAVITY", "DENY", "BLOCK")):
                d = q.get("domain", "unknown")
                blocked[d] = blocked.get(d, 0) + 1
        top_blocked_domains = [{"domain": d, "queries": float(c)} for d, c in sorted(blocked.items(), key=lambda x: -x[1])[:20]]
    except Exception as e:
        print(f"blocked: {e}")
        top_blocked_domains = []
    return True


def escape_label_value(value):
    if value is None:
        return "unknown"
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_metrics():
    lines = [
        "# HELP pihole_dns_queries_total Total DNS queries",
        "# TYPE pihole_dns_queries_total counter",
        f"pihole_dns_queries_total {metrics_cache.get('dns_queries_total', 0)}",
        "# HELP pihole_dns_blocked_total Total blocked DNS queries",
        "# TYPE pihole_dns_blocked_total counter",
        f"pihole_dns_blocked_total {metrics_cache.get('dns_blocked_total', 0)}",
        "# HELP pihole_dns_forwarded_total Total forwarded DNS queries",
        "# TYPE pihole_dns_forwarded_total counter",
        f"pihole_dns_forwarded_total {metrics_cache.get('dns_forwarded_total', 0)}",
        "# HELP pihole_dns_cached_total Total cached DNS queries",
        "# TYPE pihole_dns_cached_total counter",
        f"pihole_dns_cached_total {metrics_cache.get('dns_cached_total', 0)}",
        "# HELP pihole_clients_total Total unique clients",
        "# TYPE pihole_clients_total gauge",
        f"pihole_clients_total {metrics_cache.get('clients_total', 0)}",
        "# HELP pihole_gravity_domains Total domains in gravity blocklist",
        "# TYPE pihole_gravity_domains gauge",
        f"pihole_gravity_domains {metrics_cache.get('gravity_domains', 0)}",
        "# HELP pihole_clients_24h Unique clients in last 24 hours",
        "# TYPE pihole_clients_24h gauge",
        f"pihole_clients_24h {metrics_cache.get('clients_24h', 0)}",
    ]
    lines.append("# HELP pihole_client_queries_total DNS queries per client")
    lines.append("# TYPE pihole_client_queries_total gauge")
    for client, stats in per_client_metrics.items():
        lines.append(f'pihole_client_queries_total{{client="{escape_label_value(client)}"}} {stats["queries"]}')
    lines.append("# HELP pihole_query_type_total DNS queries by type")
    lines.append("# TYPE pihole_query_type_total gauge")
    for qtype, count in query_types.items():
        lines.append(f'pihole_query_type_total{{type="{escape_label_value(qtype)}"}} {count}')
    lines.append("# HELP pihole_upstream_queries_total Queries forwarded to upstream servers")
    lines.append("# TYPE pihole_upstream_queries_total gauge")
    for server, count in upstream_servers.items():
        lines.append(f'pihole_upstream_queries_total{{server="{escape_label_value(server)}"}} {count}')
    lines.append("# HELP pihole_top_blocked_domains_total Top blocked domains")
    lines.append("# TYPE pihole_top_blocked_domains_total gauge")
    for item in top_blocked_domains[:20]:
        lines.append(f'pihole_top_blocked_domains_total{{domain="{escape_label_value(item["domain"])}"}} {item["queries"]}')
    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = format_metrics().encode()
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
