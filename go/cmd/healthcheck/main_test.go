package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestContainerIssues(t *testing.T) {
	ps := `NAME      IMAGE      COMMAND   SERVICE   CREATED   STATUS
pihole    pihole/pihole:2026.10.0   "start.sh"   pihole   1h ago   Up 1 hour (healthy)
unbound   klutchell/unbound   "/unbound"   unbound   1h ago   Up 1 hour (unhealthy)`
	if got := ContainerIssues(ps); !reflect.DeepEqual(got, []string{"unbound_unhealthy"}) {
		t.Fatal(got)
	}
	if got := ContainerIssues(""); !reflect.DeepEqual(got, []string{"pihole_missing", "unbound_missing"}) {
		t.Fatal(got)
	}
	if got := ContainerIssues("pihole x Paused\nunbound y Up 2 min"); !reflect.DeepEqual(got, []string{"pihole_not_running"}) {
		t.Fatal(got)
	}
}

func TestStateReaders(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "w.json")
	os.WriteFile(p, []byte(`{"mode": "cloudflare"}`), 0o600)
	if WatchdogMode(p) != "cloudflare" {
		t.Fatal("mode")
	}
	os.WriteFile(p, []byte(`[1]`), 0o600)
	if WatchdogMode(p) != "unknown" {
		t.Fatal("non-dict")
	}
	n := filepath.Join(d, "n.json")
	os.WriteFile(n, []byte(`{"hash": "h1", "ts": "`+time.Now().Add(-time.Hour).Format(time.RFC3339)+`", "issues": []}`), 0o600)
	if ShouldNotify(n, "h1") || !ShouldNotify(n, "h2") {
		t.Fatal("recent")
	}
	os.WriteFile(n, []byte(`{"hash": "h1", "ts": "`+time.Now().Add(-3*time.Hour).Format(time.RFC3339)+`"}`), 0o600)
	if !ShouldNotify(n, "h1") {
		t.Fatal("old")
	}
}
