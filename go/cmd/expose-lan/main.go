// expose-lan: publish Pi-hole DNS on the LAN and allow it through the
// firewall (LAN_CIDR / LAN_IPV6_CIDR sources only). Go port of expose-lan.sh (root only).
package main

import (
	"os"
	"regexp"
	"strings"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

// prefixLen is the "/NN" of a CIDR ("24" if there is none).
func prefixLen(cidr string) string {
	if _, n, ok := strings.Cut(cidr, "/"); ok && n != "" {
		return n
	}
	return "24"
}

// lanRules are the ufw allow rules (source, port, proto, comment).
func lanRules(lanNet, lanNet6 string) [][]string {
	r := [][]string{
		{lanNet, "53", "tcp", "Pi-hole DNS LAN"},
		{lanNet, "53", "udp", "Pi-hole DNS LAN"},
		{lanNet, "853", "tcp", "Pi-hole DoT LAN"},
		{lanNet, "8443", "tcp", "Pi-hole DoH LAN"},
	}
	if lanNet6 != "" {
		r = append(r, []string{lanNet6, "53", "tcp", "Pi-hole DNS LAN IPv6"}, []string{lanNet6, "53", "udp", "Pi-hole DNS LAN IPv6"})
	}
	return r
}

func run() int {
	dir := PiholeDir()
	lanIP := conf.Need("LAN_IPV4", conf.HintLanIP)
	lanNet := conf.Need("LAN_CIDR", conf.HintLanCIDR)
	gateway := conf.Need("LAN_GATEWAY", conf.HintGateway)
	lanNet6 := conf.Get("LAN_IPV6_CIDR", "")
	probe := Probe(dir)
	dns := NewDotDNS()
	RequireRoot("./expose-lan.sh")

	Echo("==> Keep a stable Wi-Fi MAC/IP so the phone's DNS setting does not go stale")
	R("nmcli", "connection", "modify", dns.Con,
		"wifi.cloned-mac-address", "permanent",
		"ipv4.method", "manual",
		"ipv4.addresses", lanIP+"/"+prefixLen(lanNet),
		"ipv4.gateway", gateway,
		"ipv4.dns", dns.PiholeDNS,
		"connection.dns-over-tls", "yes",
		"ipv4.ignore-auto-dns", "yes",
		"ipv6.ignore-auto-dns", "yes")
	Q("nmcli", "device", "reapply", dns.Dev)

	Echo("==> Recreating Pi-hole with LAN DNS ports")
	if err := os.Chdir(dir); err != nil {
		return 1
	}
	M("docker", "compose", "up", "-d")

	if UfwActive() {
		Echo("==> Allowing DNS/admin from the LAN only (never 0.0.0.0/0 or ::/0)")
		for _, p := range []string{"53/tcp", "53/udp", "80/tcp", "443/tcp"} {
			Q("ufw", "--force", "delete", "allow", p)
		}
		for _, r := range lanRules(lanNet, lanNet6) {
			R("ufw", "allow", "from", r[0], "to", "any", "port", r[1], "proto", r[2], "comment", r[3])
		}
	}

	Echo("==> Waiting for DNS on " + lanIP)
	if !WaitProbe(probe, "example.com", lanIP, 20, "1", "/tmp/pihole-lan-probe.log") {
		CatTo(os.Stderr, "/tmp/pihole-lan-probe.log")
		M("docker", "compose", "logs", "--tail", "40")
		return 1
	}
	GrepOut(regexp.MustCompile(`:53 `), "ss", "-tuln")
	Echo("Phone DNS server: " + lanIP)
	return 0
}

func main() { shx.Main(run) }
