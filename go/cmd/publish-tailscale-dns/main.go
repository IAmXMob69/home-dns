// publish-tailscale-dns: publish Pi-hole DNS/admin on this host's
// Tailscale IPv4 (100.x); never binds 0.0.0.0 or [::]. Go port of
// publish-tailscale-dns.sh (upserts TAILSCALE_IPV4/COMPOSE_FILE in .env for
// docker-compose.tailscale.yml, recreates pihole+dnsdist).
package main

import (
	"io"
	"os"
	"regexp"
	"strings"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

var reTS = regexp.MustCompile(`^100\.([0-9]{1,3}\.){2}[0-9]{1,3}$`)

// upsertEnv mirrors the upsert_env python + chmod 600.
func upsertEnv(envFile, key, val string) {
	var lines []string
	if _, err := os.Stat(envFile); err == nil {
		lines = py.SplitLines(PyReadText(envFile))
	}
	var out []string
	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, key+"=") {
			out = append(out, key+"="+val)
			found = true
		} else {
			out = append(out, l)
		}
	}
	if !found {
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, key+"="+val)
	}
	PyWriteText(envFile, strings.Join(out, "\n")+"\n")
	shx.Chmod(0o600, envFile)
}

func waitForTSIP() (string, bool) {
	for i := 0; i < 60; i++ {
		raw, rc := shx.OutputRaw(io.Discard, "tailscale", "ip", "-4")
		ip := shx.OrEcho(raw, 0, "")
		_ = rc
		if reTS.MatchString(ip) {
			return ip, true
		}
		Sleep("1")
	}
	Err("ERROR: no Tailscale IPv4 yet. Run: tailscale up --accept-dns=false")
	return "", false
}

func run() int {
	dir := shx.Root()
	override := dir + "/docker-compose.tailscale.yml"
	envFile := dir + "/.env"
	probe := Probe(dir)
	conf.Need("LAN_IPV4", conf.HintLanIP)

	ip, ok := waitForTSIP()
	if !ok {
		return 1
	}
	if _, err := os.Stat(override); err != nil {
		Err("ERROR: " + override + " is missing. It ships with the repo; restore it with: git checkout docker-compose.tailscale.yml")
		return 1
	}

	upsertEnv(envFile, "TAILSCALE_IPV4", ip)
	upsertEnv(envFile, "COMPOSE_FILE", "docker-compose.yml:docker-compose.tailscale.yml")

	if err := os.Chdir(dir); err != nil {
		return 1
	}
	M("docker", "compose", "up", "-d", "pihole", "dnsdist")

	Echo("==> Waiting for DNS on " + ip)
	if !WaitProbe(probe, "example.com", ip, 30, "1", "/tmp/pihole-ts-probe.log") {
		CatTo(os.Stderr, "/tmp/pihole-ts-probe.log")
		shx.Cmd{Argv: []string{"docker", "compose", "logs", "--tail", "40", "pihole"}, Stdout: os.Stderr}.Run()
		return 1
	}
	Echo("Tailscale DNS: " + ip)
	GrepOut(regexp.MustCompile(`:53 `), "ss", "-tuln")
	return 0
}

func main() { shx.Main(run) }
