package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQ(t *testing.T) {
	if got := Q("Geo-Location Lock/x:y@z~_."); got != "Geo-Location%20Lock%2Fx%3Ay%40z~_." {
		t.Fatal(got)
	}
	if Q("(^|\\.)in$") != "%28%5E%7C%5C.%29in%24" {
		t.Fatal(Q("(^|\\.)in$"))
	}
}

func TestParseArgs(t *testing.T) {
	a, err := ParseArgs([]string{"--group", "G", "--description=D", "--tag", "t ", "--exact", "f:c", "--exact", "g:c2", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if *a.group != "G" || *a.description != "D" || len(a.exact) != 2 || !a.dryRun || a.noPrune {
		t.Fatalf("%+v", a)
	}
	if _, err := ParseArgs([]string{"--group", "G"}); err == nil || !strings.Contains(err.Error(), "required: --description, --tag") {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := run([]string{"--bogus"}, &out, &errb); rc != 2 {
		t.Fatal(rc)
	}
}

func TestLoadListsAndSync(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "ex.txt")
	os.WriteFile(ex, []byte("# c\nNew.COM\nold.com\nmine.com\n\n"), 0o600)
	tsv := filepath.Join(dir, "p.tsv")
	os.WriteFile(tsv, []byte("#h\n1\tT.com\tx\n2\tskip.com\ty\n3\t^re$\tz\n"), 0o600)
	tag := "tag "
	a := &Args{tag: &tag, exact: []string{ex + ":tag ex"}, tsv: []string{tsv}}
	d, err := LoadLists(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.keys) != 5 || d.vals[key{"exact", "t.com"}] != "tag x" || d.vals[key{"regex", "^re$"}] != "tag z" {
		t.Fatalf("%+v", d)
	}
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.EscapedPath()+" "+string(b))
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/groups/"):
			io.WriteString(w, `{"groups":[{"id":7,"name":"G","comment":"D","enabled":false}]}`)
		case r.Method == "GET" && r.URL.Path == "/api/domains":
			io.WriteString(w, `{"domains":[
{"type":"deny","kind":"exact","domain":"old.com","comment":"tag ex","groups":[0,7],"enabled":false},
{"type":"deny","kind":"exact","domain":"mine.com","comment":"by hand","groups":[0]},
{"type":"deny","kind":"exact","domain":"gone.com","comment":"tag ex","groups":[7]},
{"type":"allow","kind":"exact","domain":"t.com","comment":"","groups":[0]}]}`)
		case r.Method == "GET" && r.URL.Path == "/api/clients":
			io.WriteString(w, `{"clients":[{"client":"127.0.0.1","comment":"","groups":[0]},{"client":"::1","groups":[0,7]}]}`)
		default:
			io.WriteString(w, `{"processed":{"errors":[]}}`)
		}
	}))
	defer srv.Close()
	api := &Api{base: srv.URL, hc: srv.Client()}
	var out bytes.Buffer
	if err := sync(api, "G", "D", tag, d, false, true, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "G: add 3, update 1, remove 1, left alone (yours) 1\nnote: 1 of these are also on your allowlist; allow wins, untouched\n" {
		t.Fatalf("%q", out.String())
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		`POST /api/domains/deny/exact {"domain": ["new.com"], "comment": "tag ex", "groups": [7], "enabled": true}`,
		`POST /api/domains/deny/exact {"domain": ["t.com"], "comment": "tag x", "groups": [7], "enabled": true}`,
		`POST /api/domains/deny/regex {"domain": ["^re$"], "comment": "tag z", "groups": [7], "enabled": true}`,
		`PUT /api/domains/deny/exact/old.com {"type": "deny", "kind": "exact", "comment": "tag ex", "groups": [7], "enabled": false}`,
		`POST /api/domains:batchDelete [{"item": "gone.com", "type": "deny", "kind": "exact"}]`,
		`PUT /api/clients/127.0.0.1 {"comment": "This computer", "groups": [0, 7]}`,
		`POST /api/clients {"client": "0.0.0.0/0", "comment": "All IPv4 devices, so the group switch applies house-wide", "groups": [0, 7]}`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing call %s\n--- got:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "/api/clients/%3A%3A1") {
		t.Error("::1 already has both groups")
	}
}
