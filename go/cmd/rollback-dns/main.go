// rollback-dns: put this machine back on Cloudflare/Google DNS without
// touching Pi-hole files. Go port of rollback-dns.sh (root only).
package main

import (
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

func run() int {
	con, dev := NetLink()
	RequireRoot("./rollback-dns.sh")
	M("nmcli", "connection", "modify", con,
		"ipv4.dns", "1.1.1.1,8.8.8.8",
		"ipv6.dns", "2606:4700:4700::1111,2001:4860:4860::8888",
		"ipv4.ignore-auto-dns", "yes",
		"ipv6.ignore-auto-dns", "yes")
	if R("nmcli", "device", "reapply", dev) != 0 {
		M("resolvectl", "dns", dev, "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888")
	}
	Echo("DNS restored to 1.1.1.1 / 8.8.8.8.")
	R("getent", "hosts", "example.com")
	return 0
}

func main() { shx.Main(run) }
