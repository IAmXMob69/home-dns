package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatLine(t *testing.T) {
	got := FormatLine("plain", "127.0.0.1", "example.com", 0, 2, []string{"1.2.3.4", "5.6.7.8"}, 61)
	want := "mode=plain server=127.0.0.1 host=example.com rcode=0 answers=2 addrs=1.2.3.4,5.6.7.8 status=ok bytes=61\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(FormatLine("dot", "s", "h", 0, 1, []string{"0.0.0.0"}, 1), "status=BLOCKED") {
		t.Fatal("blocked")
	}
	if !strings.Contains(FormatLine("plain", "s", "h", 2, 0, nil, 12), "addrs=- status=fail") {
		t.Fatal("fail")
	}
	if !strings.Contains(FormatLine("plain", "s", "h", 3, 0, nil, 12), "status=ok") {
		t.Fatal("nxdomain ok")
	}
}

func TestBadServer(t *testing.T) {
	var out, errb bytes.Buffer
	// Label too long -> error before any network.
	rc := run([]string{strings.Repeat("a", 70) + ".com"}, &out, &errb)
	if rc != 1 || !strings.HasPrefix(errb.String(), "DNS probe failed: ") || out.Len() != 0 {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
}
