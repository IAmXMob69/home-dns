// apply-stack: bring up Pi-hole + Unbound, curated lists, and verify DNS
// before switching this PC. Go port of apply-stack.sh (root only).
package main

import (
	"os"

	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

const addLists = `
INSERT INTO adlist (address, enabled, comment)
SELECT 'https://small.oisd.nl/', 1, 'OISD small'
WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = 'https://small.oisd.nl/');
INSERT INTO adlist (address, enabled, comment)
SELECT 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-dnscrypt-blocked-names.txt', 1, 'URLhaus malware names'
WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-dnscrypt-blocked-names.txt');
`

func run() int {
	dir := PiholeDir()
	probe := Probe(dir)
	dns := NewDotDNS()
	RequireRoot("./apply-stack.sh")

	ChmodAll(0o644, Globs(dir+"/unbound/custom.conf.d/*.conf")...)

	Echo("==> Temporarily using Cloudflare while the stack recreates")
	dns.FailoverPublic(true)

	Echo("==> Starting Unbound + Pi-hole")
	if err := os.Chdir(dir); err != nil {
		return 1
	}
	M("docker", "compose", "pull", "unbound")
	M("docker", "compose", "up", "-d")

	Echo("==> Waiting for Unbound (DNSSEC)")
	ready := false
	for i := 0; i < 40; i++ {
		if Q("docker", "exec", "unbound", "drill-hc", "@127.0.0.1", "dnssec.works") == 0 ||
			Q("docker", "exec", "unbound", "drill", "@127.0.0.1", "dnssec.works") == 0 {
			ready = true
			break
		}
		Sleep("3")
	}
	if !ready {
		M("docker", "compose", "logs", "--tail", "80", "unbound")
		Err("ERROR: Unbound did not become healthy")
		return 1
	}

	Echo("==> Waiting for Pi-hole on 127.0.0.1")
	if !WaitProbe(probe, "example.com", "127.0.0.1", 40, "2", "/tmp/pihole-stack-probe.log") {
		CatTo(os.Stderr, "/tmp/pihole-stack-probe.log")
		M("docker", "compose", "logs", "--tail", "80", "pihole")
		Err("Keeping Cloudflare DNS because Pi-hole did not come back")
		return 1
	}

	Echo("==> Adding quality blocklists (idempotent)")
	R("docker", "exec", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", addLists)

	Echo("==> Updating gravity")
	if R("docker", "exec", "pihole", "pihole", "-g") != 0 {
		R("docker", "exec", "pihole", "/opt/pihole/gravity.sh")
	}

	Echo("==> Pointing this machine back at Pi-hole DoT")
	dns.RestorePihole(true)
	Sleep("1")
	GetentHead2("example.com")
	ProbeRC(probe, "doubleclick.net", "127.0.0.1")
	Echo("Stack is live.")
	return 0
}

func main() { shx.Main(run) }
