// Package conf reads host settings for the Go tools: the environment
// first, then KEY=VALUE lines in <root>/.env (root is shx.Root()).
// Need exits with a plain-English message when a setting is missing or
// still holds a placeholder from .env.example.
package conf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"pihole/go/internal/shx"
)

var (
	once    sync.Once
	fileEnv map[string]string
	// EnvFile overrides <root>/.env (tests, PIHOLE_ENV_FILE).
	EnvFile = ""
)

// ParseEnv reads KEY=VALUE lines (comments, blank lines and an optional
// "export " prefix are ignored; one layer of matching quotes is removed).
func ParseEnv(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		l = strings.TrimPrefix(l, "export ")
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

func load() {
	p := EnvFile
	if p == "" {
		p = os.Getenv("PIHOLE_ENV_FILE")
	}
	if p == "" {
		p = filepath.Join(shx.Root(), ".env")
	}
	fileEnv = map[string]string{}
	if b, err := os.ReadFile(p); err == nil {
		fileEnv = ParseEnv(string(b))
	}
}

// Reset drops the cached .env (tests).
func Reset() { once = sync.Once{} }

// Get returns the setting: env, then .env, then def.
func Get(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	once.Do(load)
	if v := fileEnv[key]; v != "" {
		return v
	}
	return def
}

// Set reports whether a setting has a real (non-placeholder) value.
func Set(key string) bool { return !IsPlaceholder(Get(key, "")) }

// IsPlaceholder: empty, or a value copied unchanged from .env.example.
func IsPlaceholder(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	switch {
	case l == "":
		return true
	case strings.Contains(l, "your-"), strings.Contains(l, "your_"),
		strings.Contains(l, "change-me"), strings.Contains(l, "x.x"),
		strings.HasSuffix(l, ".x"):
		return true
	}
	return false
}

// Missing formats the message Need prints.
func Missing(tool, key, what string) string {
	return fmt.Sprintf("%s: %s is not set. %s\nAdd %s=... to .env (see .env.example) or export it, then run this again.",
		tool, key, what, key)
}

// Need returns the setting or exits 2 with a plain-English message.
func Need(key, what string) string {
	v := Get(key, "")
	if IsPlaceholder(v) {
		fmt.Fprintln(os.Stderr, Missing(filepath.Base(shx.Argv0(os.Args[0])), key, what))
		os.Exit(2)
	}
	return v
}

// Hints for the settings several tools share.
const (
	HintWifiCon = "It is the NetworkManager connection this PC uses for its LAN (list: nmcli -t -f NAME,DEVICE connection show --active)."
	HintWifiDev = "It is the network device of that connection, e.g. wlan0 or eth0 (list: nmcli device)."
	HintDotName = "It is the name in the DoT certificate, e.g. the MagicDNS name from tailscale status, or pihole.lan with the self-signed cert."
	HintLanIP   = "It is this PC's fixed LAN IPv4 address."
	HintLanCIDR = "It is your LAN network, e.g. 192.168.1.0/24."
	HintGateway = "It is your router's LAN IPv4 address."
	HintUser    = "It is the login that owns the checkout (run with sudo so SUDO_USER is set, or set PIHOLE_USER)."
)
