// fix-pihole: safe Pi-hole bring-up for Arch + systemd-resolved; never
// points this machine at Pi-hole until 127.0.0.1:53 answers. Go port of
// fix-pihole.sh (root only).
package main

import (
	"os"
	"regexp"

	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

var dns DotDNS

func restoreHostDNS() {
	Echo("==> Restoring Cloudflare/Google DoT on " + dns.Con)
	dns.FailoverPublic(false)
}

func fail(msg string) {
	Err("ERROR: " + msg)
	restoreHostDNS()
	shx.Fail(1)
}

func run() int {
	dir := PiholeDir()
	user := Owner()
	probe := Probe(dir)
	dns = NewDotDNS()
	RequireRoot("./fix-pihole.sh")
	argv0 := shx.Argv0("./fix-pihole.sh")

	Echo("==> Installing/starting Docker")
	M("pacman", "-S", "--needed", "--noconfirm", "docker", "docker-compose")
	M("systemctl", "enable", "--now", "docker")
	R("usermod", "-aG", "docker", user)

	Echo("==> Stopping the old host-network Pi-hole (it could not bind port 53)")
	if err := os.Chdir(dir); err != nil {
		return 1
	}
	R("docker", "compose", "down", "--remove-orphans")

	Echo("==> Disabling systemd-resolved's stub listener on port 53")
	M("rm", "-f", "/etc/systemd/resolved.conf.d/fix.conf")
	M("install", "-d", "/etc/systemd/resolved.conf.d")
	WriteHeredoc(argv0, "/etc/systemd/resolved.conf.d/no-stub.conf", "[Resolve]\nDNSStubListener=no\n", 51)
	shx.Chmod(0o644, "/etc/systemd/resolved.conf.d/no-stub.conf")
	M("ln", "-sfn", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")
	M("systemctl", "daemon-reload")
	M("systemctl", "stop", "systemd-resolved")
	Sleep("1")
	M("systemctl", "start", "systemd-resolved")
	Sleep("1")

	if PipeQ(regexp.MustCompile(`127\.0\.0\.53`), "ss", "-tuln") {
		Echo("WARNING: 127.0.0.53 is still present; continuing with 127.0.0.1-only Docker ports")
	} else {
		Echo("systemd-resolved stub is gone")
	}

	Echo("==> Checking internet still works via 1.1.1.1")
	if ProbeRC(probe, "example.com", "1.1.1.1") != 0 {
		fail("Cloudflare DNS stopped answering")
	}

	Echo("==> Starting Pi-hole on 127.0.0.1:53")
	M("install", "-d", "-o", user, "-g", user, dir+"/etc-pihole")
	M("docker", "compose", "up", "-d")

	Echo("==> Waiting for Pi-hole DNS on 127.0.0.1:53")
	if !WaitProbe(probe, "example.com", "127.0.0.1", 30, "2", "/tmp/pihole-dns-probe.log") {
		Err("Pi-hole DNS did not answer. Last probe:")
		CatTo(os.Stderr, "/tmp/pihole-dns-probe.log")
		M("docker", "compose", "logs", "--tail", "100")
		fail("refusing to point this machine at a dead resolver")
	}

	Echo("==> Confirming Pi-hole answers a block-list domain")
	if ProbeRC(probe, "doubleclick.net", "127.0.0.1") != 0 {
		fail("Pi-hole did not answer a block-list query")
	}

	if UfwActive() {
		Echo("==> Allowing the web UI through UFW (DNS is loopback-only)")
		R("ufw", "allow", "80/tcp", "comment", "Pi-hole web")
		R("ufw", "allow", "443/tcp", "comment", "Pi-hole web TLS")
	}

	Echo("==> Pointing this machine at Pi-hole DoT")
	dns.RestorePihole(true)
	Sleep("2")

	Echo("==> Checking the full resolver path")
	f, err := os.OpenFile("/tmp/pihole-getent.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	rc := 1
	if err == nil {
		rc = shx.Cmd{Argv: []string{"getent", "hosts", "example.com"}, Stdout: f}.Run()
		f.Close()
	}
	if rc != 0 {
		CatTo(os.Stderr, "/tmp/pihole-getent.log")
		fail("hostname lookup still broken after switching DNS")
	}
	CatTo(os.Stdout, "/tmp/pihole-getent.log")
	if ProbeRC(probe, "example.com", "127.0.0.1") != 0 {
		fail("Pi-hole stopped answering after the DNS switch")
	}

	Blank()
	Echo("Pi-hole is up and this machine's DNS is using it.")
	Echo("Dashboard: http://127.0.0.1/admin/")
	Echo("Password is in " + dir + "/.env")
	Echo("If lookups break: sudo " + dir + "/rollback-dns.sh")
	return 0
}

func main() { shx.Main(run) }
