package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnv(t *testing.T) {
	m := ParseEnv("# c\nA=1\nexport B=\"two words\"\nC='x'\n\nbad line\nD=\n")
	if m["A"] != "1" || m["B"] != "two words" || m["C"] != "x" || m["D"] != "" {
		t.Fatalf("got %v", m)
	}
}

func TestPlaceholder(t *testing.T) {
	for _, v := range []string{"", " ", "192.168.1.X", "100.x.x.x", "your-host.your-tailnet.ts.net", "change-me-too", "YOUR_SSID"} {
		if !IsPlaceholder(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	for _, v := range []string{"192.0.2.10", "wlan0", "home-wifi", "pihole.lan", "198.51.100.0/24"} {
		if IsPlaceholder(v) {
			t.Errorf("%q should be a real value", v)
		}
	}
}

func TestGetOrder(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte("CONF_T_A=file\nCONF_T_B=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	EnvFile = p
	Reset()
	t.Cleanup(func() { EnvFile = ""; Reset() })
	t.Setenv("CONF_T_A", "env")
	if got := Get("CONF_T_A", "def"); got != "env" {
		t.Errorf("env first: %q", got)
	}
	if got := Get("CONF_T_B", "def"); got != "file" {
		t.Errorf(".env second: %q", got)
	}
	if got := Get("CONF_T_C", "def"); got != "def" {
		t.Errorf("default last: %q", got)
	}
}

func TestMissing(t *testing.T) {
	m := Missing("harden", "WIFI_CON", HintWifiCon)
	if !strings.Contains(m, "WIFI_CON is not set") || !strings.Contains(m, ".env.example") {
		t.Fatal(m)
	}
}
