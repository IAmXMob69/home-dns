// pihole-groups: sync a toggleable Pi-hole group through the Pi-hole v6 API.
// Go port of ~/pihole/scripts/lib/pihole_groups.py (same flags, output,
// API calls and exit codes).
//
// Never writes gravity.db directly. Rules:
//   - Only deny entries are created. Allow entries are never touched.
//   - An entry is "ours" when its comment starts with --tag. Only ours get
//     updated, and ours that are no longer in the source lists get deleted.
//   - A deny entry the user added by hand (other comment) is left alone.
//   - The group's on/off switch is kept as the user left it.
//   - Ours live only in this group (not Default), so the switch really
//     turns them off. Their existing comments are kept.
//
// Password: PIHOLE_PASSWORD, else FTLCONF_webserver_api_password from .env.
// .env is looked up in $PIHOLE_ROOT, else two levels above the binary
// (<root>/go/bin -> <root>), else $HOME/pihole.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pihole/go/internal/py"
)

const prog = "pihole_groups.py"

type client struct{ ip, comment string }

var clients = []client{
	{"0.0.0.0/0", "All IPv4 devices, so the group switch applies house-wide"},
	{"::/0", "All IPv6 devices"},
	{"127.0.0.1", "This computer"},
	{"::1", "This computer IPv6"},
	{"192.168.0.0/16", "Typical home LAN"},
	{"10.0.0.0/8", "Private LAN"},
	{"172.16.0.0/12", "Private LAN / Docker"},
}

type ApiError struct{ msg string }

func (e *ApiError) Error() string { return e.msg }

func apiErr(f string, a ...any) error { return &ApiError{fmt.Sprintf(f, a...)} }

func readEnvPassword(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range py.SplitLines(string(raw)) {
		key, val, sep := strings.Cut(py.Strip(line), "=")
		if sep && key == "FTLCONF_webserver_api_password" {
			return strings.Trim(py.Strip(val), `'"`)
		}
	}
	return ""
}

type Api struct {
	base string
	sid  string
	hc   *http.Client
}

func NewApi(base, password string) (*Api, error) {
	a := &Api{base: strings.TrimRight(base, "/"), hc: &http.Client{Timeout: 60 * time.Second}}
	if password != "" {
		r, err := a.call("POST", "/api/auth", py.O("password", password), false)
		if err != nil {
			return nil, err
		}
		sess, _ := asMap(r).Get("session")
		if !py.Truthy(sess) {
			sess = nil
		}
		sid, _ := asMap(sess).Get("sid")
		if s, ok := sid.(string); ok && s != "" {
			a.sid = s
		} else {
			return nil, apiErr("Pi-hole rejected the password")
		}
	}
	return a, nil
}

func asMap(v any) *py.Map {
	if m, ok := v.(*py.Map); ok {
		return m
	}
	return nil
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// call returns the decoded JSON (nil for GET 404).
func (a *Api) call(method, path string, body any, auth bool) (any, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader([]byte(py.Dumps(body, false)))
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		return nil, apiErr("cannot reach Pi-hole at %s: %v", a.base, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth && a.sid != "" {
		req.Header.Set("X-FTL-SID", a.sid)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		reason := err
		if errors.As(err, &ue) {
			reason = ue.Unwrap()
		}
		return nil, apiErr("cannot reach Pi-hole at %s: %s", a.base, py.ErrStr(reason))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apiErr("cannot reach Pi-hole at %s: %v", a.base, err)
	}
	if resp.StatusCode >= 400 {
		if resp.StatusCode == 404 && method == "GET" {
			return nil, nil
		}
		detail := []rune(string(bytes.ToValidUTF8(raw, []byte("\uFFFD"))))
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return nil, apiErr("%s %s: HTTP %d %s", method, path, resp.StatusCode, string(detail))
	}
	if len(raw) == 0 {
		return py.NewMap(), nil
	}
	v, err := py.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%s %s: bad JSON: %v", method, path, err)
	}
	return v, nil
}

func (a *Api) logout() {
	if a.sid != "" {
		_, _ = a.call("DELETE", "/api/auth", nil, true)
	}
}

// Q mimics urllib.parse.quote(s, safe="").
func Q(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func numEq(a, b any) bool {
	fa, ea := py.ToFloat(a)
	fb, eb := py.ToFloat(b)
	return ea == nil && eb == nil && fa == fb
}

func ensureGroup(a *Api, name, desc string, dry bool, out io.Writer) (any, error) {
	r, err := a.call("GET", "/api/groups/"+Q(name), nil, true)
	if err != nil {
		return nil, err
	}
	gv, _ := asMap(r).Get("groups")
	groups := asList(gv)
	if len(groups) > 0 {
		g := asMap(groups[0])
		if c, _ := g.Get("comment"); !(isStr(c, desc)) && !dry {
			if _, err := a.call("PUT", "/api/groups/"+Q(name),
				py.O("name", name, "comment", desc, "enabled", g.GetOr("enabled", true)), true); err != nil {
				return nil, err
			}
		}
		id, ok := g.Get("id")
		if !ok {
			return nil, errors.New("KeyError: 'id'")
		}
		return id, nil
	}
	if dry {
		fmt.Fprintf(out, "would create group '%s'\n", name)
		return -1, nil
	}
	r, err = a.call("POST", "/api/groups", py.O("name", name, "comment", desc, "enabled", true), true)
	if err != nil {
		return nil, err
	}
	gv, _ = asMap(r).Get("groups")
	for _, g := range asList(gv) {
		if n, _ := asMap(g).Get("name"); isStr(n, name) {
			id, _ := asMap(g).Get("id")
			return id, nil
		}
	}
	r, err = a.call("GET", "/api/groups/"+Q(name), nil, true)
	if err != nil {
		return nil, err
	}
	gv, _ = asMap(r).Get("groups")
	if l := asList(gv); len(l) > 0 {
		id, _ := asMap(l[0]).Get("id")
		return id, nil
	}
	return nil, errors.New("group not found after create")
}

func isStr(v any, s string) bool {
	x, ok := v.(string)
	return ok && x == s
}

func strOr(v any, def string) string {
	if py.Truthy(v) {
		return py.Str(v)
	}
	return def
}

func checkProcessed(r any, what string) error {
	p, _ := asMap(r).Get("processed")
	if !py.Truthy(p) {
		return nil
	}
	ev, _ := asMap(p).Get("errors")
	errs := asList(ev)
	if len(errs) > 0 {
		if len(errs) > 5 {
			errs = errs[:5]
		}
		return apiErr("%s: %s", what, py.Repr(errs))
	}
	return nil
}

type key struct{ kind, domain string }

// Desired is an insertion-ordered dict {(kind, domain): comment}.
type Desired struct {
	keys []key
	vals map[key]string
}

func newDesired() *Desired { return &Desired{vals: map[key]string{}} }

func (d *Desired) set(k key, v string) {
	if _, ok := d.vals[k]; !ok {
		d.keys = append(d.keys, k)
	}
	d.vals[k] = v
}

func groupIDs(v any) []float64 {
	var out []float64
	for _, g := range asList(v) {
		if f, err := py.ToFloat(g); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func toJSONIDs(ids []float64) []any {
	out := make([]any, len(ids))
	for i, f := range ids {
		if f == float64(int64(f)) {
			out[i] = int(f)
		} else {
			out[i] = f
		}
	}
	return out
}

func sync(a *Api, group, desc, tag string, desired *Desired, dry, prune bool, out io.Writer) error {
	gidV, err := ensureGroup(a, group, desc, dry, out)
	if err != nil {
		return err
	}
	gid, _ := py.ToFloat(gidV)
	r, err := a.call("GET", "/api/domains", nil, true)
	if err != nil {
		return err
	}
	dv, _ := asMap(r).Get("domains")
	type entry struct {
		k key
		d *py.Map
	}
	denyKeys := []key{}
	deny := map[key]*py.Map{}
	allow := map[key]bool{}
	for _, it := range asList(dv) {
		d := asMap(it)
		k := key{py.Str(d.GetOr("kind", nil)), py.Str(d.GetOr("domain", nil))}
		t, _ := d.Get("type")
		if isStr(t, "deny") {
			if _, ok := deny[k]; !ok {
				denyKeys = append(denyKeys, k)
			}
			deny[k] = d
		} else if isStr(t, "allow") {
			allow[k] = true
		}
	}
	type addKey struct{ kind, comment string }
	addOrder := []addKey{}
	toAdd := map[addKey][]string{}
	type fix struct {
		k       key
		comment string
		have    *py.Map
	}
	var toFix []fix
	skipped := 0
	for _, k := range desired.keys {
		comment := desired.vals[k]
		have, ok := deny[k]
		hc := strOr(have.GetOr("comment", nil), "")
		switch {
		case !ok:
			ak := addKey{k.kind, comment}
			if _, seen := toAdd[ak]; !seen {
				addOrder = append(addOrder, ak)
			}
			toAdd[ak] = append(toAdd[ak], k.domain)
		case !strings.HasPrefix(hc, tag):
			skipped++
		default:
			g := groupIDs(have.GetOr("groups", nil))
			sort.Float64s(g)
			if !(len(g) == 1 && g[0] == gid) {
				toFix = append(toFix, fix{k, strOr(have.GetOr("comment", nil), comment), have})
			}
		}
	}
	var stale []entry
	for _, k := range denyKeys {
		d := deny[k]
		if _, want := desired.vals[k]; strings.HasPrefix(strOr(d.GetOr("comment", nil), ""), tag) && !want {
			stale = append(stale, entry{k, d})
		}
	}
	nAdd := 0
	for _, v := range toAdd {
		nAdd += len(v)
	}
	nRemove := 0
	if prune {
		nRemove = len(stale)
	}
	fmt.Fprintf(out, "%s: add %d, update %d, remove %d, left alone (yours) %d\n", group, nAdd, len(toFix), nRemove, skipped)
	shadowed := 0
	for _, k := range desired.keys {
		if allow[k] {
			shadowed++
		}
	}
	if shadowed > 0 {
		fmt.Fprintf(out, "note: %d of these are also on your allowlist; allow wins, untouched\n", shadowed)
	}
	if dry {
		return nil
	}
	gidJ := toJSONIDs([]float64{gid})
	for _, ak := range addOrder {
		domains := toAdd[ak]
		for i := 0; i < len(domains); i += 500 {
			j := min(i+500, len(domains))
			batch := make([]any, 0, j-i)
			for _, d := range domains[i:j] {
				batch = append(batch, d)
			}
			r, err := a.call("POST", "/api/domains/deny/"+ak.kind,
				py.O("domain", batch, "comment", ak.comment, "groups", gidJ, "enabled", true), true)
			if err != nil {
				return err
			}
			if err := checkProcessed(r, "add "+ak.kind); err != nil {
				return err
			}
		}
	}
	for _, f := range toFix {
		r, err := a.call("PUT", "/api/domains/deny/"+f.k.kind+"/"+Q(f.k.domain),
			py.O("type", "deny", "kind", f.k.kind, "comment", f.comment, "groups", gidJ,
				"enabled", f.have.GetOr("enabled", true)), true)
		if err != nil {
			return err
		}
		if err := checkProcessed(r, "update "+f.k.domain); err != nil {
			return err
		}
	}
	if prune && len(stale) > 0 {
		for i := 0; i < len(stale); i += 500 {
			j := min(i+500, len(stale))
			batch := []any{}
			for _, e := range stale[i:j] {
				batch = append(batch, py.O("item", e.d.GetOr("domain", nil), "type", "deny", "kind", e.d.GetOr("kind", nil)))
			}
			if _, err := a.call("POST", "/api/domains:batchDelete", batch, true); err != nil {
				return err
			}
		}
	}
	r, err = a.call("GET", "/api/clients", nil, true)
	if err != nil {
		return err
	}
	cv, _ := asMap(r).Get("clients")
	have := map[string]*py.Map{}
	for _, c := range asList(cv) {
		m := asMap(c)
		have[py.Str(m.GetOr("client", nil))] = m
	}
	for _, c := range clients {
		h, ok := have[c.ip]
		if !ok {
			if _, err := a.call("POST", "/api/clients",
				py.O("client", c.ip, "comment", c.comment, "groups", toJSONIDs([]float64{0, gid})), true); err != nil {
				return err
			}
			continue
		}
		g := groupIDs(h.GetOr("groups", nil))
		set := map[float64]bool{}
		for _, x := range g {
			set[x] = true
		}
		if !(set[0] && set[gid]) {
			set[0], set[gid] = true, true
			var u []float64
			for x := range set {
				u = append(u, x)
			}
			sort.Float64s(u)
			if _, err := a.call("PUT", "/api/clients/"+Q(c.ip),
				py.O("comment", strOr(h.GetOr("comment", nil), c.comment), "groups", toJSONIDs(u)), true); err != nil {
				return err
			}
		}
	}
	return nil
}

type Args struct {
	group, description, tag *string
	exact, regex, tsv       []string
	api                     string
	dryRun, noPrune         bool
}

const usage = "usage: " + prog + ` [-h] --group GROUP --description DESCRIPTION --tag TAG
                        [--exact FILE:COMMENT] [--regex FILE:COMMENT]
                        [--tsv FILE] [--api API] [--dry-run] [--no-prune]
`

const help = usage + `
Sync a toggleable Pi-hole group through the Pi-hole v6 API.

options:
  -h, --help            show this help message and exit
  --group GROUP
  --description DESCRIPTION
  --tag TAG             comment prefix that marks entries this script owns
  --exact FILE:COMMENT
  --regex FILE:COMMENT
  --tsv FILE            type<TAB>domain<TAB>comment rows
  --api API
  --dry-run
  --no-prune
`

var valueOpts = []string{"--group", "--description", "--tag", "--exact", "--regex", "--tsv", "--api"}
var flagOpts = []string{"--dry-run", "--no-prune", "--help"}

type usageErr struct{ msg string }

func (e *usageErr) Error() string { return e.msg }

func resolveOpt(name string) (string, error) {
	all := append(append([]string{}, valueOpts...), flagOpts...)
	for _, o := range all {
		if o == name {
			return o, nil
		}
	}
	var hits []string
	for _, o := range all {
		if strings.HasPrefix(o, name) {
			hits = append(hits, o)
		}
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	if len(hits) > 1 {
		return "", &usageErr{fmt.Sprintf("ambiguous option: %s could match %s", name, strings.Join(hits, ", "))}
	}
	return "", nil
}

// ParseArgs mimics the argparse setup in pihole_groups.py.
func ParseArgs(argv []string) (*Args, error) {
	a := &Args{api: os.Getenv("PIHOLE_API")}
	if a.api == "" {
		a.api = "http://127.0.0.1"
	}
	var unknown []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "-h" {
			return nil, &usageErr{"help"}
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			unknown = append(unknown, arg)
			continue
		}
		name, val, hasVal := strings.Cut(arg, "=")
		opt, err := resolveOpt(name)
		if err != nil {
			return nil, err
		}
		if opt == "" {
			unknown = append(unknown, arg)
			continue
		}
		if opt == "--help" {
			return nil, &usageErr{"help"}
		}
		isValue := false
		for _, o := range valueOpts {
			if o == opt {
				isValue = true
			}
		}
		if !isValue {
			if hasVal {
				return nil, &usageErr{fmt.Sprintf("argument %s: ignored explicit argument '%s'", opt, val)}
			}
			if opt == "--dry-run" {
				a.dryRun = true
			} else {
				a.noPrune = true
			}
			continue
		}
		if !hasVal {
			if i+1 >= len(argv) || (strings.HasPrefix(argv[i+1], "-") && len(argv[i+1]) > 1) {
				return nil, &usageErr{fmt.Sprintf("argument %s: expected one argument", metaName(opt))}
			}
			i++
			val = argv[i]
		}
		switch opt {
		case "--group":
			a.group = &val
		case "--description":
			a.description = &val
		case "--tag":
			a.tag = &val
		case "--exact":
			a.exact = append(a.exact, val)
		case "--regex":
			a.regex = append(a.regex, val)
		case "--tsv":
			a.tsv = append(a.tsv, val)
		case "--api":
			a.api = val
		}
	}
	var missing []string
	if a.group == nil {
		missing = append(missing, "--group")
	}
	if a.description == nil {
		missing = append(missing, "--description")
	}
	if a.tag == nil {
		missing = append(missing, "--tag")
	}
	if len(missing) > 0 {
		return nil, &usageErr{"the following arguments are required: " + strings.Join(missing, ", ")}
	}
	if len(unknown) > 0 {
		return nil, &usageErr{"unrecognized arguments: " + strings.Join(unknown, " ")}
	}
	return a, nil
}

func metaName(opt string) string {
	switch opt {
	case "--exact", "--regex":
		return opt + " FILE:COMMENT"
	case "--tsv":
		return "--tsv FILE"
	}
	return opt + " " + strings.ToUpper(strings.TrimPrefix(opt, "--"))
}

func readLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[Errno 2] No such file or directory: %s", py.Repr(path))
	}
	return py.SplitLines(string(raw)), nil
}

// LoadLists mirrors load_lists(args).
func LoadLists(a *Args) (*Desired, error) {
	d := newDesired()
	for _, spec := range a.exact {
		path, comment, _ := strings.Cut(spec, ":")
		lines, err := readLines(path)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			dom := strings.ToLower(py.Strip(line))
			if dom != "" && !strings.HasPrefix(dom, "#") {
				d.set(key{"exact", dom}, comment)
			}
		}
	}
	for _, spec := range a.regex {
		path, comment, _ := strings.Cut(spec, ":")
		lines, err := readLines(path)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			dom := py.Strip(line)
			if dom != "" && !strings.HasPrefix(dom, "#") {
				d.set(key{"regex", dom}, comment)
			}
		}
	}
	for _, path := range a.tsv {
		lines, err := readLines(path)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			if py.Strip(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) < 3 {
				continue
			}
			t := py.Strip(parts[0])
			if t != "1" && t != "3" {
				continue
			}
			kind, dom := "regex", py.Strip(parts[1])
			if t == "1" {
				kind, dom = "exact", strings.ToLower(dom)
			}
			d.set(key{kind, dom}, *a.tag+py.Strip(parts[2]))
		}
	}
	return d, nil
}

func rootDir() string {
	if r := os.Getenv("PIHOLE_ROOT"); r != "" {
		return r
	}
	if exe, err := os.Executable(); err == nil {
		r := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
		if _, err := os.Stat(filepath.Join(r, ".env")); err == nil {
			return r
		}
	}
	return filepath.Join(os.Getenv("HOME"), "pihole")
}

func run(argv []string, stdout, stderr io.Writer) int {
	a, err := ParseArgs(argv)
	if err != nil {
		if err.Error() == "help" {
			fmt.Fprint(stdout, help)
			return 0
		}
		fmt.Fprint(stderr, usage)
		fmt.Fprintf(stderr, "%s: error: %s\n", prog, err)
		return 2
	}
	desired, err := LoadLists(a)
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		return 1
	}
	seen := map[string]bool{}
	for _, k := range desired.keys {
		c := desired.vals[k]
		if seen[c] {
			continue
		}
		seen[c] = true
		if !strings.HasPrefix(c, *a.tag) {
			fmt.Fprintf(stderr, "comment '%s' must start with tag '%s'\n", c, *a.tag)
			return 1
		}
	}
	password := os.Getenv("PIHOLE_PASSWORD")
	if password == "" {
		password = readEnvPassword(filepath.Join(rootDir(), ".env"))
	}
	api, err := NewApi(a.api, password)
	if err == nil {
		err = sync(api, *a.group, *a.description, *a.tag, desired, a.dryRun, !a.noPrune, stdout)
		api.logout()
	}
	if err != nil {
		fmt.Fprintf(stderr, "pihole-groups: %s\n", err)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
