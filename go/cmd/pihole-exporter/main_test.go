package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fakePihole(t *testing.T, blockedFails bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			io.WriteString(w, `{"session":{"valid":true,"sid":"S1","csrf":"C1"}}`)
		case "/api/stats/summary":
			if r.Header.Get("X-FTL-SID") != "S1" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"queries":{"total":100,"blocked":7,"forwarded":50,"cached":43,"types":{"A":60,"AAAA":30,"HTTPS":10}},"clients":{"active":3,"total":5},"gravity":{"domains_being_blocked":123456}}`)
		case "/api/stats/top_domains":
			if r.URL.Query().Get("blocked") == "true" {
				if blockedFails {
					w.WriteHeader(500)
					return
				}
				io.WriteString(w, `{"domains":[{"domain":"ads.example","count":5}]}`)
				return
			}
			io.WriteString(w, `{"domains":[{"domain":"a\"b.com","count":9},{"domain":null,"count":1}]}`)
		case "/api/stats/top_clients":
			io.WriteString(w, `{"clients":[{"ip":"127.0.0.1","name":"localhost","count":80},{"ip":"172.30.90.1","name":"","count":20}]}`)
		case "/api/stats/upstreams":
			io.WriteString(w, `{"upstreams":[{"ip":"blocklist","name":"blocklist","count":7},{"ip":"172.30.90.4","name":null,"count":50}]}`)
		case "/api/queries":
			io.WriteString(w, `{"queries":[{"domain":"x.in","status":"REGEX"},{"domain":"y.com","status":"FORWARDED"},{"domain":"x.in","status":"GRAVITY"},{"domain":"z.ng","status":4}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestFetchAndFormat(t *testing.T) {
	srv := fakePihole(t, false)
	defer srv.Close()
	e := NewExporter()
	e.base, e.password, e.log = srv.URL, "pw", &bytes.Buffer{}
	e.Fetch() // first call gets 401, logs in, retries
	out := Format(e.snap)
	for _, want := range []string{
		"# HELP pihole_up 1 if the Pi-hole API answered the last scrape\n# TYPE pihole_up gauge\npihole_up 1.0\n",
		"pihole_dns_queries_total 100.0\n",
		"pihole_gravity_domains 123456.0\n",
		"pihole_clients_24h 3.0\n",
		"pihole_clients_total 5.0\n",
		`pihole_query_type_total{type="A"} 60.0` + "\n" + `pihole_query_type_total{type="AAAA"} 30.0` + "\n" + `pihole_query_type_total{type="HTTPS"} 10.0`,
		`pihole_client_queries_total{client="127.0.0.1"} 80.0`,
		`pihole_upstream_queries_total{server="172.30.90.4"} 50.0`,
		`pihole_top_permitted_domains_total{domain="a\"b.com"} 9.0`,
		`pihole_top_permitted_domains_total{domain="unknown"} 1.0`,
		`pihole_top_blocked_domains_total{domain="ads.example"} 5.0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "# TYPE") != 17 {
		t.Fatal("shape")
	}
}

func TestBlockedSampleFallback(t *testing.T) {
	srv := fakePihole(t, true)
	defer srv.Close()
	e := NewExporter()
	e.base, e.password, e.log = srv.URL, "pw", &bytes.Buffer{}
	e.Fetch()
	out := Format(e.snap)
	if !strings.Contains(out, `pihole_top_blocked_domains_total{domain="x.in"} 2.0`+"\n"+`pihole_top_blocked_domains_total{domain="z.ng"} 1.0`) {
		t.Fatal(out)
	}
}

func TestSqliteFallback(t *testing.T) {
	e := NewExporter()
	e.base, e.dbPath = "http://127.0.0.1:1", "/nonexistent/ftl.db"
	var logb bytes.Buffer
	e.log = &logb
	e.Fetch()
	out := Format(e.snap)
	if !strings.Contains(out, "pihole_up 0.0\n") || !strings.Contains(out, "pihole_dns_queries_total 0.0\n") {
		t.Fatal(out)
	}
	if !strings.Contains(logb.String(), "API summary failed, using sqlite fallback") || !strings.Contains(logb.String(), "sqlite: ") {
		t.Fatal(logb.String())
	}
}

func TestServe(t *testing.T) {
	e := NewExporter()
	srv := httptest.NewServer(e)
	defer srv.Close()
	for path, code := range map[string]int{"/metrics": 200, "/health": 200, "/metrics?x=1": 404, "/": 404} {
		r, err := http.Get(srv.URL + path)
		if err != nil || r.StatusCode != code {
			t.Errorf("%s: %v %v", path, r.StatusCode, err)
		}
	}
	r, _ := http.Get(srv.URL + "/metrics")
	if r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal(r.Header)
	}
}

func TestExtraMetrics(t *testing.T) {
	t.Setenv("EXTRA_METRICS_FILE", "")
	if ExtraMetrics() != "" {
		t.Fatal("unset should be empty")
	}
	f := t.TempDir() + "/nft.prom"
	t.Setenv("EXTRA_METRICS_FILE", f)
	if ExtraMetrics() != "" {
		t.Fatal("missing file should be empty")
	}
	if err := os.WriteFile(f, []byte("home_dns_nft_counters_up 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ExtraMetrics(); got != "home_dns_nft_counters_up 1\n" {
		t.Fatalf("%q", got)
	}
	srv := httptest.NewServer(NewExporter())
	defer srv.Close()
	r, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.HasSuffix(string(body), "pihole_top_blocked_domains_total Top blocked domains (gravity, regex, deny)\n# TYPE pihole_top_blocked_domains_total gauge\nhome_dns_nft_counters_up 1\n") {
		t.Fatalf("%q", body)
	}
}
