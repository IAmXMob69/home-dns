// harden: lock Pi-hole/Unbound/Grafana to this PC + LAN (LAN_CIDR,
// optional LAN_IPV6_CIDR) + Tailscale. Go port of
// harden.sh (root only; same chmods, compose recreate, UFW rules,
// DOCKER-USER blocks in /etc/ufw/after{,6}.rules and live iptables).
package main

import (
	"os"
	"regexp"
	"strings"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

// v4Block is the after.rules DOCKER-USER block: LAN, loopback, Docker,
// Tailscale CGNAT, then drop.
func v4Block(lanNet string) string {
	return `# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ` + lanNet + ` -j RETURN
-A DOCKER-USER -s 127.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 100.64.0.0/10 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user`
}

// v6Block is the after6.rules block. lanNet6 (LAN_IPV6_CIDR) is optional.
func v6Block(lanNet6 string) string {
	lan := ""
	if lanNet6 != "" {
		lan = "-A DOCKER-USER -s " + lanNet6 + " -j RETURN\n"
	}
	return `# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ::1 -j RETURN
-A DOCKER-USER -s fe80::/10 -j RETURN
-A DOCKER-USER -s fd00::/8 -j RETURN
-A DOCKER-USER -s fd7a:115c:a1e0::/48 -j RETURN
` + lan + `-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user`
}

// ufwRules are the LAN and Tailscale allow rules (args after "ufw allow").
func ufwRules(lanNet, lanNet6 string) [][]string {
	r := [][]string{
		{"from", lanNet, "to", "any", "port", "53", "proto", "tcp", "comment", "Pi-hole DNS LAN"},
		{"from", lanNet, "to", "any", "port", "53", "proto", "udp", "comment", "Pi-hole DNS LAN"},
		{"from", lanNet, "to", "any", "port", "853", "proto", "tcp", "comment", "Pi-hole DoT LAN"},
		{"from", lanNet, "to", "any", "port", "8443", "proto", "tcp", "comment", "Pi-hole DoH LAN"},
	}
	if lanNet6 != "" {
		r = append(r,
			[]string{"from", lanNet6, "to", "any", "port", "53", "proto", "tcp", "comment", "Pi-hole DNS LAN IPv6"},
			[]string{"from", lanNet6, "to", "any", "port", "53", "proto", "udp", "comment", "Pi-hole DNS LAN IPv6"})
	}
	return append(r,
		[]string{"in", "on", "tailscale0", "to", "any", "port", "53", "proto", "tcp", "comment", "Pi-hole DNS Tailscale"},
		[]string{"in", "on", "tailscale0", "to", "any", "port", "53", "proto", "udp", "comment", "Pi-hole DNS Tailscale"},
		[]string{"in", "on", "tailscale0", "to", "any", "port", "853", "proto", "tcp", "comment", "Pi-hole DoT Tailscale"},
		[]string{"in", "on", "tailscale0", "to", "any", "port", "8443", "proto", "tcp", "comment", "Pi-hole DoH Tailscale"},
		[]string{"in", "on", "tailscale0", "to", "any", "port", "443", "proto", "tcp", "comment", "Tailscale Serve HTTPS"})
}

// rulesOf turns a block's "-A DOCKER-USER ..." lines into iptables args.
func rulesOf(block string) [][]string {
	var out [][]string
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "-A DOCKER-USER ") {
			out = append(out, strings.Fields(strings.TrimPrefix(l, "-A DOCKER-USER ")))
		}
	}
	return out
}

var reUfwNum = regexp.MustCompile(`^\[\s*([0-9]+)\] *(53|80|443|3000)/.*`)

func run() int {
	dir := PiholeDir()
	user := Owner()
	lanNet := conf.Need("LAN_CIDR", conf.HintLanCIDR)
	lanIP := conf.Need("LAN_IPV4", conf.HintLanIP)
	lanNet6 := conf.Get("LAN_IPV6_CIDR", "")
	probe := Probe(dir)
	dns := NewDotDNS()
	RequireRoot("./harden.sh")

	Echo("==> Tightening secret and config permissions")
	must(ChmodAll(0o700, dir))
	must(ChmodAll(0o600, dir+"/.env", dir+"/docker-compose.yml"))
	must(ChmodAll(0o700, dir+"/etc-pihole"))
	ChmodAll(0o600, dir+"/etc-pihole/cli_pw", dir+"/etc-pihole/tls.pem", dir+"/etc-pihole/tls.crt", dir+"/etc-pihole/tls_ca.crt")
	must(ChmodAll(0o644, Globs(dir+"/unbound/custom.conf.d/*.conf")...))
	must(ChmodAll(0o755, dir+"/unbound", dir+"/unbound/custom.conf.d"))
	must(ChmodAll(0o755, dir+"/monitoring", dir+"/monitoring/prometheus"))
	must(ChmodAll(0o644, dir+"/monitoring/prometheus/prometheus.yml"))
	must(ChmodAll(0o755, dir+"/monitoring/grafana",
		dir+"/monitoring/grafana/dashboards",
		dir+"/monitoring/grafana/provisioning",
		dir+"/monitoring/grafana/provisioning/dashboards",
		dir+"/monitoring/grafana/provisioning/datasources"))
	must(ChmodAll(0o644, Globs(dir+"/monitoring/grafana/dashboards/*.json",
		dir+"/monitoring/grafana/provisioning/dashboards/*.yml",
		dir+"/monitoring/grafana/provisioning/datasources/*.yml")...))
	M("chown", "-R", user+":"+user, dir+"/.env", dir+"/docker-compose.yml")

	Echo("==> Temporarily using Cloudflare while published ports recreate")
	dns.FailoverPublic(true)

	Echo("==> Recreating stack with IPv4-only host binds")
	if err := os.Chdir(dir); err != nil {
		return 1
	}
	M("docker", "compose", "down", "--remove-orphans")
	M("docker", "compose", "up", "-d")

	Echo("==> Waiting for Pi-hole DNS on 127.0.0.1")
	if !WaitProbe(probe, "example.com", "127.0.0.1", 40, "2", "/tmp/pihole-harden-probe.log") {
		CatTo(os.Stderr, "/tmp/pihole-harden-probe.log")
		M("docker", "compose", "logs", "--tail", "80", "pihole")
		Err("Keeping Cloudflare DNS because Pi-hole did not come back")
		return 1
	}

	Echo("==> Replacing world-open UFW 53/80/443 with LAN-only rules")
	if CommandV("ufw") {
		out, _ := shx.OutputRaw(os.Stderr, "ufw", "status", "numbered")
		var nums []string
		for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if m := reUfwNum.FindStringSubmatch(l); m != nil {
				nums = append(nums, m[1])
			}
		}
		SortNR(nums)
		if len(nums) == 0 {
			nums = []string{""} // "${ufw_nums[@]:-}" on an empty array
		}
		for _, n := range nums {
			Q("ufw", "--force", "delete", n)
		}
		for _, r := range ufwRules(lanNet, lanNet6) {
			R(append([]string{"ufw", "allow"}, r...)...)
		}
	}

	Echo("==> Persisting DOCKER-USER drop for non-LAN sources")
	UpsertBlock("/etc/ufw/after.rules", PyRstrip(v4Block(lanNet))+"\n")
	UpsertBlock("/etc/ufw/after6.rules", PyRstrip(v6Block(lanNet6))+"\n")

	Iptables("iptables", rulesOf(v4Block(lanNet)))
	Iptables("ip6tables", rulesOf(v6Block(lanNet6)))

	if CommandV("ufw") {
		if rc := QOut("ufw", "reload"); rc != 0 {
			return rc
		}
	}

	Echo("==> Pointing this machine back at Pi-hole DoT")
	dns.RestorePihole(true)
	Sleep("1")

	Echo("==> Verifying binds and DNS")
	GrepOut(regexp.MustCompile(`:53 |:853 |:8443 |:80 |:443 |:3000 |:9090 |:9617 `), "ss", "-tuln")
	M(append(append([]string{}, probe...), "example.com", "127.0.0.1")...)
	M(append(append([]string{}, probe...), "example.com", lanIP)...)
	GetentHead2("example.com")
	Echo("Harden complete.")
	return 0
}

func must(rc int) {
	if rc != 0 {
		shx.Fail(rc)
	}
}

func main() { shx.Main(run) }
