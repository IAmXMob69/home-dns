package main

import (
	"strings"
	"testing"
)

func TestUpArgs(t *testing.T) {
	if got := strings.Join(upArgs("", ""), " "); got != "tailscale up --accept-dns=false --advertise-exit-node" {
		t.Fatal(got)
	}
	if got := strings.Join(upArgs("alice", "dns-box"), " "); !strings.HasSuffix(got, "--operator=alice --hostname=dns-box") {
		t.Fatal(got)
	}
}
