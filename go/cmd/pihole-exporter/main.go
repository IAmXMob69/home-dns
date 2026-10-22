// pihole-exporter: Pi-hole Prometheus exporter (v6 auth + volume DB).
// Go port of ~/pihole/monitoring/pihole-exporter.py: same env vars, port,
// metric names, labels, HELP text and value formatting.
package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"pihole/go/internal/py"
)

const (
	cacheTTL = 30 * time.Second
	topN     = 20
)

var (
	blockedStatusIDs   = []int{1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}
	cachedStatusIDs    = []int{3, 17}
	blockedStatusNames = map[string]bool{
		"GRAVITY": true, "REGEX": true, "DENYLIST": true,
		"EXTERNAL_BLOCKED_IP": true, "EXTERNAL_BLOCKED_NULL": true, "EXTERNAL_BLOCKED_NXRA": true,
		"EXTERNAL_BLOCKED_EDE15": true,
		"GRAVITY_CNAME":          true, "REGEX_CNAME": true, "DENYLIST_CNAME": true,
		"DBBUSY": true, "SPECIAL_DOMAIN": true,
	}
)

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

// Pair is one labeled sample.
type Pair struct {
	Key string
	Val float64
}

// OrderedFloats is a Python-dict-like ordered map of label -> value.
type OrderedFloats struct {
	keys []string
	vals map[string]float64
}

func newOF() *OrderedFloats { return &OrderedFloats{vals: map[string]float64{}} }

func (o *OrderedFloats) Set(k string, v float64) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *OrderedFloats) Pairs() []Pair {
	if o == nil {
		return nil
	}
	out := make([]Pair, len(o.keys))
	for i, k := range o.keys {
		out[i] = Pair{k, o.vals[k]}
	}
	return out
}

// Snapshot is everything format_metrics reads.
type Snapshot struct {
	Up           float64
	Metrics      map[string]float64
	Clients      *OrderedFloats
	QueryTypes   *OrderedFloats
	Upstreams    *OrderedFloats
	TopPermitted []Pair
	TopBlocked   []Pair
}

type Exporter struct {
	base     string
	password string
	dbPath   string
	hc       *http.Client
	hdr      http.Header
	mu       sync.Mutex
	snap     Snapshot
	log      io.Writer
}

func NewExporter() *Exporter {
	jar, _ := cookiejar.New(nil)
	e := &Exporter{
		base: fmt.Sprintf("%s://%s:%s", getenv("PIHOLE_PROTOCOL", "http"),
			getenv("PIHOLE_HOSTNAME", "pihole"), getenv("PIHOLE_PORT", "80")),
		password: getenv("PIHOLE_PASSWORD", ""),
		dbPath:   getenv("FTL_DB_PATH", "/etc/pihole/pihole-FTL.db"),
		hc:       &http.Client{Timeout: 10 * time.Second, Jar: jar},
		hdr:      http.Header{},
		log:      os.Stdout,
	}
	e.snap = Snapshot{Metrics: map[string]float64{}, Clients: newOF(), QueryTypes: newOF(), Upstreams: newOF()}
	return e
}

func (e *Exporter) logf(f string, a ...any) { fmt.Fprintf(e.log, f+"\n", a...) }

func (e *Exporter) do(method, url string, body []byte) (*http.Response, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range e.hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp, raw, err
}

func (e *Exporter) login() {
	if e.password == "" {
		return
	}
	body := []byte(py.Dumps(py.O("password", e.password), false))
	resp, raw, err := e.do("POST", e.base+"/api/auth", body)
	if err != nil {
		e.logf("Pi-hole auth error: %v", err)
		return
	}
	var data any = py.NewMap()
	if len(raw) > 0 {
		if data, err = py.Decode(raw); err != nil {
			e.logf("Pi-hole auth error: %v", err)
			return
		}
	}
	dm, ok := data.(*py.Map)
	if !ok {
		e.logf("Pi-hole auth error: 'list' object has no attribute 'get'")
		return
	}
	sess, ok := dm.GetOr("session", py.NewMap()).(*py.Map)
	if !ok {
		e.logf("Pi-hole auth error: object has no attribute 'get'")
		return
	}
	sid := sess.GetOr("sid", nil)
	csrf := sess.GetOr("csrf", "")
	if py.Truthy(sid) {
		e.hdr.Set("X-FTL-SID", py.Str(sid))
		if py.Truthy(csrf) {
			e.hdr.Set("X-FTL-CSRF", py.Str(csrf))
		}
		e.logf("Authenticated to Pi-hole v6 API")
	} else {
		e.logf("Pi-hole auth failed: HTTP %d", resp.StatusCode)
	}
}

func reasonFor(code int) string { return http.StatusText(code) }

func (e *Exporter) apiGet(path string) (*py.Map, error) {
	url := e.base + path
	resp, raw, err := e.do("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		e.login()
		if resp, raw, err = e.do("GET", url, nil); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode >= 400 {
		kind := "Client"
		if resp.StatusCode >= 500 {
			kind = "Server"
		}
		return nil, fmt.Errorf("%d %s Error: %s for url: %s", resp.StatusCode, kind, reasonFor(resp.StatusCode), url)
	}
	v, err := py.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("Expecting value: %v", err)
	}
	m, ok := v.(*py.Map)
	if !ok {
		return nil, fmt.Errorf("'list' object has no attribute 'get'")
	}
	return m, nil
}

// sub returns d.get(k, {}) as a map, or an error if it is not one.
func sub(d *py.Map, k string) (*py.Map, error) {
	v := d.GetOr(k, py.NewMap())
	m, ok := v.(*py.Map)
	if !ok {
		return nil, fmt.Errorf("'%T' object has no attribute 'get'", v)
	}
	return m, nil
}

func list(d *py.Map, k string) ([]any, error) {
	v := d.GetOr(k, []any{})
	l, ok := v.([]any)
	if !ok {
		if m, ok := v.(*py.Map); ok { // iterating a dict yields keys
			out := make([]any, len(m.Keys))
			for i, k := range m.Keys {
				out[i] = k
			}
			return out, nil
		}
		return nil, fmt.Errorf("'%T' object is not iterable", v)
	}
	return l, nil
}

func fget(d *py.Map, k string) (float64, error) { return py.ToFloat(d.GetOr(k, 0)) }

func labelKey(v any) string {
	if v == nil {
		return "unknown"
	}
	return py.Str(v)
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}

func (e *Exporter) sqliteScalar(q string, def float64) float64 {
	db, err := sql.Open("sqlite", "file:"+e.dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		e.logf("sqlite: %v", err)
		return def
	}
	defer db.Close()
	var v any
	if err := db.QueryRow(q).Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return def
		}
		e.logf("sqlite: %v", err)
		return def
	}
	if v == nil {
		return def
	}
	f, err := py.ToFloat(v)
	if err != nil {
		e.logf("sqlite: %v", err)
		return def
	}
	return f
}

func (e *Exporter) summary(s *Snapshot) error {
	data, err := e.apiGet("/api/stats/summary")
	if err != nil {
		return err
	}
	queries, err := sub(data, "queries")
	if err != nil {
		return err
	}
	clients, err := sub(data, "clients")
	if err != nil {
		return err
	}
	gravity, err := sub(data, "gravity")
	if err != nil {
		return err
	}
	type src struct {
		name string
		m    *py.Map
		k    string
	}
	m := map[string]float64{}
	for _, x := range []src{
		{"dns_queries_total", queries, "total"}, {"dns_blocked_total", queries, "blocked"},
		{"dns_forwarded_total", queries, "forwarded"}, {"dns_cached_total", queries, "cached"},
		{"clients_total", clients, "total"}, {"devices_total", clients, "total"},
		{"devices_active_24h", clients, "active"}, {"dns_queries_24h", queries, "total"},
		{"dns_blocked_24h", queries, "blocked"}, {"dns_forwarded_24h", queries, "forwarded"},
		{"dns_cached_24h", queries, "cached"}, {"clients_24h", clients, "active"},
		{"gravity_domains", gravity, "domains_being_blocked"},
	} {
		f, err := fget(x.m, x.k)
		if err != nil {
			return err
		}
		m[x.name] = f
	}
	s.Metrics = m
	qt := newOF()
	tv := queries.GetOr("types", nil)
	if tm, ok := tv.(*py.Map); ok {
		for _, k := range tm.Keys {
			f, err := py.ToFloat(tm.Vals[k])
			if err != nil {
				return err
			}
			qt.Set(k, f)
		}
	} else if py.Truthy(tv) {
		return fmt.Errorf("'%T' object has no attribute 'items'", tv)
	}
	s.QueryTypes = qt
	s.Up = 1
	return nil
}

func (e *Exporter) sqliteFallback(s *Snapshot) {
	since := "timestamp >= CAST(strftime('%s','now') AS INTEGER) - 86400"
	b, c := joinInts(blockedStatusIDs), joinInts(cachedStatusIDs)
	total := e.sqliteScalar("SELECT COUNT(*) FROM query_storage WHERE "+since, 0)
	blocked := e.sqliteScalar("SELECT COUNT(*) FROM query_storage WHERE "+since+" AND status IN ("+b+")", 0)
	forwarded := e.sqliteScalar("SELECT COUNT(*) FROM query_storage WHERE "+since+" AND status=2", 0)
	cached := e.sqliteScalar("SELECT COUNT(*) FROM query_storage WHERE "+since+" AND status IN ("+c+")", 0)
	clients := e.sqliteScalar("SELECT COUNT(DISTINCT client) FROM query_storage WHERE "+since, 0)
	ct := e.sqliteScalar("SELECT COUNT(*) FROM client_by_id", 0)
	dt := e.sqliteScalar("SELECT COUNT(*) FROM client_by_id", 0)
	s.Metrics = map[string]float64{
		"dns_queries_total": total, "dns_blocked_total": blocked, "dns_forwarded_total": forwarded,
		"dns_cached_total": cached, "clients_total": ct, "devices_total": dt,
		"devices_active_24h": clients, "dns_queries_24h": total, "dns_blocked_24h": blocked,
		"dns_forwarded_24h": forwarded, "dns_cached_24h": cached, "clients_24h": clients,
		"gravity_domains": e.sqliteScalar("SELECT value FROM counters WHERE id=0", 0),
	}
}

func items(data *py.Map, k string) ([]*py.Map, error) {
	l, err := list(data, k)
	if err != nil {
		return nil, err
	}
	out := make([]*py.Map, 0, len(l))
	for _, it := range l {
		m, ok := it.(*py.Map)
		if !ok {
			return nil, fmt.Errorf("'%T' object has no attribute 'get'", it)
		}
		out = append(out, m)
	}
	return out, nil
}

func (e *Exporter) topDomains(path string) ([]Pair, error) {
	data, err := e.apiGet(path)
	if err != nil {
		return nil, err
	}
	its, err := items(data, "domains")
	if err != nil {
		return nil, err
	}
	out := []Pair{}
	for _, it := range its {
		f, err := fget(it, "count")
		if err != nil {
			return nil, err
		}
		out = append(out, Pair{labelKey(it.GetOr("domain", "unknown")), f})
	}
	return out, nil
}

func isBlockedStatus(v any) bool {
	switch t := v.(type) {
	case bool:
		x := 0
		if t {
			x = 1
		}
		return contains(blockedStatusIDs, x)
	case string:
		return blockedStatusNames[strings.ToUpper(t)]
	case nil:
		return false
	}
	if f, err := py.ToFloat(v); err == nil {
		if s := py.Str(v); !strings.Contains(s, ".") {
			return contains(blockedStatusIDs, int(f))
		}
		return blockedStatusNames[strings.ToUpper(py.Str(v))]
	}
	return blockedStatusNames[strings.ToUpper(py.Str(v))]
}

func contains(xs []int, x int) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}

func (e *Exporter) sampleBlocked() []Pair {
	data, err := e.apiGet("/api/queries?length=500")
	if err != nil {
		e.logf("blocked sample: %v", err)
		return []Pair{}
	}
	its, err := items(data, "queries")
	if err != nil {
		e.logf("blocked sample: %v", err)
		return []Pair{}
	}
	counts := newOF()
	for _, q := range its {
		if isBlockedStatus(q.GetOr("status", nil)) {
			d := labelKey(q.GetOr("domain", "unknown"))
			counts.Set(d, counts.vals[d]+1)
		}
	}
	p := counts.Pairs()
	sort.SliceStable(p, func(i, j int) bool { return p[i].Val > p[j].Val })
	if len(p) > topN {
		p = p[:topN]
	}
	return p
}

// Fetch mirrors fetch_pihole_stats().
func (e *Exporter) Fetch() {
	e.mu.Lock()
	s := e.snap
	e.mu.Unlock()

	if err := e.summary(&s); err != nil {
		e.logf("API summary failed, using sqlite fallback: %v", err)
		s.Up = 0
		e.sqliteFallback(&s)
	}

	if p, err := e.topDomains(fmt.Sprintf("/api/stats/top_domains?count=%d", topN)); err != nil {
		e.logf("top domains: %v", err)
		s.TopPermitted = nil
	} else {
		s.TopPermitted = p
	}

	if data, err := e.apiGet("/api/stats/top_clients"); err != nil {
		e.logf("top clients: %v", err)
		s.Clients = newOF()
	} else if its, err := items(data, "clients"); err != nil {
		e.logf("top clients: %v", err)
		s.Clients = newOF()
	} else {
		c := newOF()
		var ferr error
		for _, it := range its {
			f, err := fget(it, "count")
			if err != nil {
				ferr = err
				break
			}
			c.Set(labelKey(it.GetOr("ip", "unknown")), f)
		}
		if ferr != nil {
			e.logf("top clients: %v", ferr)
			c = newOF()
		}
		s.Clients = c
	}

	if data, err := e.apiGet("/api/stats/upstreams"); err != nil {
		e.logf("upstreams: %v", err)
		s.Upstreams = newOF()
	} else if its, err := items(data, "upstreams"); err != nil {
		e.logf("upstreams: %v", err)
		s.Upstreams = newOF()
	} else {
		u := newOF()
		var ferr error
		for _, it := range its {
			name := it.GetOr("name", nil)
			if !py.Truthy(name) {
				name = it.GetOr("ip", "unknown")
			}
			f, err := fget(it, "count")
			if err != nil {
				ferr = err
				break
			}
			u.Set(labelKey(name), f)
		}
		if ferr != nil {
			e.logf("upstreams: %v", ferr)
			u = newOF()
		}
		s.Upstreams = u
	}

	if p, err := e.topDomains(fmt.Sprintf("/api/stats/top_domains?blocked=true&count=%d", topN)); err != nil {
		e.logf("top blocked domains: %v; sampling recent queries", err)
		s.TopBlocked = e.sampleBlocked()
	} else {
		s.TopBlocked = p
	}

	e.mu.Lock()
	e.snap = s
	e.mu.Unlock()
}

// EscapeLabel mirrors escape_label_value.
func EscapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}

// Format renders the snapshot exactly like format_metrics().
func Format(s Snapshot) string {
	var b strings.Builder
	val := func(k string) string {
		if v, ok := s.Metrics[k]; ok {
			return py.Float(v)
		}
		return "0"
	}
	gauge := func(name, help, v string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, help, name, name, v)
	}
	labeled := func(name, help, label string, ps []Pair) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, p := range ps {
			fmt.Fprintf(&b, "%s{%s=\"%s\"} %s\n", name, label, EscapeLabel(p.Key), py.Float(p.Val))
		}
	}
	gauge("pihole_up", "1 if the Pi-hole API answered the last scrape", py.Float(s.Up))
	gauge("pihole_dns_queries_total", "DNS queries (last 24h)", val("dns_queries_total"))
	gauge("pihole_dns_blocked_total", "Blocked DNS queries (last 24h)", val("dns_blocked_total"))
	gauge("pihole_dns_forwarded_total", "Forwarded DNS queries (last 24h)", val("dns_forwarded_total"))
	gauge("pihole_dns_cached_total", "Cached DNS queries (last 24h)", val("dns_cached_total"))
	gauge("pihole_dns_queries_24h", "DNS queries in the last 24 hours", val("dns_queries_24h"))
	gauge("pihole_dns_blocked_24h", "Blocked DNS queries in the last 24 hours", val("dns_blocked_24h"))
	gauge("pihole_dns_forwarded_24h", "Forwarded DNS queries in the last 24 hours", val("dns_forwarded_24h"))
	gauge("pihole_dns_cached_24h", "Cached DNS queries in the last 24 hours", val("dns_cached_24h"))
	gauge("pihole_clients_total", "Total unique clients", val("clients_total"))
	gauge("pihole_clients_24h", "Unique clients in last 24 hours", val("clients_24h"))
	gauge("pihole_gravity_domains", "Total domains in gravity blocklist", val("gravity_domains"))
	labeled("pihole_client_queries_total", "DNS queries per client", "client", s.Clients.Pairs())
	labeled("pihole_query_type_total", "DNS queries by type", "type", s.QueryTypes.Pairs())
	labeled("pihole_upstream_queries_total", "Queries forwarded to upstream servers", "server", s.Upstreams.Pairs())
	tp, tb := s.TopPermitted, s.TopBlocked
	if len(tp) > topN {
		tp = tp[:topN]
	}
	if len(tb) > topN {
		tb = tb[:topN]
	}
	labeled("pihole_top_permitted_domains_total", "Top permitted domains", "domain", tp)
	labeled("pihole_top_blocked_domains_total", "Top blocked domains (gravity, regex, deny)", "domain", tb)
	return b.String()
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	switch r.RequestURI {
	case "/metrics":
		e.mu.Lock()
		body := Format(e.snap)
		e.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		io.WriteString(w, body)
	case "/health":
		w.Header()["Content-Type"] = nil
		w.WriteHeader(200)
		io.WriteString(w, "OK")
	default:
		w.WriteHeader(404)
	}
}

func main() {
	port := getenv("EXPORTER_PORT", "9617")
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Fprintf(os.Stderr, "invalid literal for int() with base 10: %s\n", py.Repr(port))
		os.Exit(1)
	}
	e := NewExporter()
	e.logf("Starting Pi-hole exporter on %s", port)
	e.login()
	e.Fetch()
	go func() {
		for {
			e.Fetch()
			time.Sleep(cacheTTL)
		}
	}()
	srv := &http.Server{Addr: "0.0.0.0:" + port, Handler: e, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
