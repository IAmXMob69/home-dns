// setup-tailscale-privileged: root helper for the Tailscale package, UFW,
// DOCKER-USER and the pihole-tailscale-dns.service republish unit. Go port
// of setup-tailscale-privileged.sh (root only).
package main

import (
	osuser "os/user"
	"strings"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

const unit = "/etc/systemd/system/pihole-tailscale-dns.service"

func v4(lanNet string) string {
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
# END pihole-docker-user
`
}

const v6 = `# BEGIN pihole-docker-user
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s ::1 -j RETURN
-A DOCKER-USER -s fe80::/10 -j RETURN
-A DOCKER-USER -s fd00::/8 -j RETURN
-A DOCKER-USER -s fd7a:115c:a1e0::/48 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END pihole-docker-user
`

// unitText is the boot-time republish unit for user's checkout at dir.
func unitText(user, home, dir string) string {
	return `[Unit]
Description=Publish Pi-hole DNS on Tailscale IPv4
After=tailscaled.service docker.service
Wants=tailscaled.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=` + user + `
Group=` + user + `
SupplementaryGroups=docker
Environment=HOME=` + home + `
Environment=USER=` + user + `
WorkingDirectory=` + dir + `
ExecStart=` + dir + `/publish-tailscale-dns.sh

[Install]
WantedBy=multi-user.target
`
}

func rulesOf(block string) [][]string {
	var out [][]string
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "-A DOCKER-USER ") {
			out = append(out, strings.Fields(strings.TrimPrefix(l, "-A DOCKER-USER ")))
		}
	}
	return out
}

func run() int {
	dir := PiholeDir()
	user := Owner()
	lanNet := conf.Need("LAN_CIDR", conf.HintLanCIDR)
	RequireRoot("./setup-tailscale-privileged.sh")
	home := dir
	if u, err := osuser.Lookup(user); err == nil {
		home = u.HomeDir
	}

	Echo("==> Installing Tailscale (extra) and bind (dig). Not enabling named.")
	M("pacman", "-S", "--needed", "--noconfirm", "tailscale", "bind")
	QErr("systemctl", "disable", "--now", "named.service")

	Echo("==> Enabling tailscaled (kernel wireguard, tailscale0)")
	M("systemctl", "enable", "--now", "tailscaled")
	QErr("tailscale", "set", "--operator="+user)

	Echo("==> UFW: UDP/TCP 53 on tailscale0 only. Never 53 from the WAN.")
	if CommandV("ufw") {
		Q("ufw", "--force", "delete", "allow", "53/tcp")
		Q("ufw", "--force", "delete", "allow", "53/udp")
		R("ufw", "allow", "41641/udp", "comment", "Tailscale WireGuard")
		R("ufw", "allow", "in", "on", "tailscale0", "to", "any", "port", "53", "proto", "tcp", "comment", "Pi-hole DNS Tailscale")
		R("ufw", "allow", "in", "on", "tailscale0", "to", "any", "port", "53", "proto", "udp", "comment", "Pi-hole DNS Tailscale")
		R("ufw", "allow", "in", "on", "tailscale0", "to", "any", "port", "443", "proto", "tcp", "comment", "Tailscale Serve HTTPS")
	}

	Echo("==> DOCKER-USER: allow Tailscale CGNAT, drop everything else (no WAN 53)")
	UpsertBlock("/etc/ufw/after.rules", v4(lanNet))
	UpsertBlock("/etc/ufw/after6.rules", v6)

	Iptables("iptables", rulesOf(v4(lanNet)))
	Iptables("ip6tables", rulesOf(v6))

	if CommandV("ufw") {
		if rc := QOut("ufw", "reload"); rc != 0 {
			return rc
		}
	}

	Echo("==> systemd: republish Pi-hole on Tailscale IP after boot")
	WriteHeredoc(shx.Argv0("./setup-tailscale-privileged.sh"), unit, unitText(user, home, dir), 117)
	M("systemctl", "daemon-reload")
	M("systemctl", "enable", "pihole-tailscale-dns.service")

	Echo("==> Not changing this host's DNS (keep 127.0.0.1 -> Pi-hole -> Unbound).")
	Echo("    Tailscale on this host MUST stay: tailscale up --accept-dns=false")
	Echo("Privileged setup done.")
	return 0
}

func main() { shx.Main(run) }
