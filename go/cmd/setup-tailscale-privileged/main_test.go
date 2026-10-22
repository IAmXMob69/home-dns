package main

import (
	"strings"
	"testing"
)

func TestUnitText(t *testing.T) {
	u := unitText("alice", "/srv/alice", "/srv/alice/home-dns")
	for _, want := range []string{"User=alice\n", "Environment=HOME=/srv/alice\n", "WorkingDirectory=/srv/alice/home-dns\n", "ExecStart=/srv/alice/home-dns/publish-tailscale-dns.sh\n"} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestV4(t *testing.T) {
	if r := rulesOf(v4("198.51.100.0/24")); len(r) != 8 || r[1][1] != "198.51.100.0/24" {
		t.Fatal(r)
	}
}
