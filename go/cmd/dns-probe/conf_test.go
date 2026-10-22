package main

import (
	"testing"

	"pihole/go/internal/conf"
)

func TestDefaultServerName(t *testing.T) {
	conf.EnvFile = "/nonexistent"
	conf.Reset()
	t.Cleanup(func() { conf.EnvFile = ""; conf.Reset() })
	t.Setenv("DOT_AUTH_NAME", "your-host.your-tailnet.ts.net")
	if got := defaultServerName(); got != "pihole.lan" {
		t.Fatalf("placeholder: %s", got)
	}
	t.Setenv("DOT_AUTH_NAME", "dns.example.net")
	if got := defaultServerName(); got != "dns.example.net" {
		t.Fatalf("set: %s", got)
	}
}
