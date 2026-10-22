package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pihole/go/internal/py"
)

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath = filepath.Join(dir, "state", "watchdog.json")
	s := loadState()
	saveState(s)
	b, _ := os.ReadFile(statePath)
	want := `{"mode": "pihole", "fail": 0, "ok": 0, "last_heal": null, "last_notify": null, "heal_tried": false}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	os.WriteFile(statePath, []byte(`{"mode":"cloudflare","fail":4,"ok":0,"last_heal":"2026-10-22T06:00:00-04:00","extra":1,"heal_tried":true}`), 0o600)
	s = loadState()
	if !s.modeIs("cloudflare") || py.ToInt(s.get("fail")) != 4 || !py.Truthy(s.get("heal_tried")) {
		t.Fatal("load")
	}
	saveState(s)
	b, _ = os.ReadFile(statePath)
	if string(b) != `{"mode": "cloudflare", "fail": 4, "ok": 0, "last_heal": "2026-10-22T06:00:00-04:00", "last_notify": null, "heal_tried": true}` {
		t.Fatalf("got %s", b)
	}
	os.WriteFile(statePath, []byte(`[1]`), 0o600)
	if !loadState().modeIs("pihole") {
		t.Fatal("non-dict state should reset")
	}
}

func TestLogLine(t *testing.T) {
	logPath = filepath.Join(t.TempDir(), "logs", "w.log")
	logLine("check", "mode", "pihole", "loopback", true, "fail", 0)
	b, _ := os.ReadFile(logPath)
	line := string(b)
	if !strings.HasPrefix(line, `{"ts":"`) || !strings.HasSuffix(line, `","event":"check","mode":"pihole","loopback":true,"fail":0}`+"\n") {
		t.Fatalf("got %s", line)
	}
}

func TestCooldown(t *testing.T) {
	s := defaultState()
	if !healCooldownOK(s) {
		t.Fatal("no last_heal")
	}
	s.set("last_heal", isoNow())
	if healCooldownOK(s) {
		t.Fatal("just healed")
	}
	s.set("last_heal", time.Now().Add(-11*time.Minute).Format("2006-01-02T15:04:05-07:00"))
	if !healCooldownOK(s) {
		t.Fatal("old heal")
	}
	s.set("last_heal", "garbage")
	if !healCooldownOK(s) {
		t.Fatal("bad value")
	}
}
