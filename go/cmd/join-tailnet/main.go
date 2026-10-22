// join-tailnet: bring this host onto the tailnet WITHOUT Tailscale DNS.
// Go port of join-tailnet.sh.
package main

import (
	"io"
	"os"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

// upArgs builds `tailscale up`. An empty operator or hostname is left out
// (Tailscale then uses root-only control and the OS hostname).
func upArgs(operator, hostname string) []string {
	a := []string{"tailscale", "up", "--accept-dns=false", "--advertise-exit-node"}
	if operator != "" {
		a = append(a, "--operator="+operator)
	}
	if hostname != "" {
		a = append(a, "--hostname="+hostname)
	}
	return a
}

func run() int {
	if !CommandV("tailscale") {
		Err("Install Tailscale first: sudo " + shx.Root() + "/setup-tailscale-privileged.sh")
		return 1
	}
	M(append(upArgs(conf.Get("TS_OPERATOR", os.Getenv("USER")), conf.Get("TS_HOSTNAME", "")), os.Args[1:]...)...)
	M("tailscale", "set", "--accept-dns=false")
	M("tailscale", "set", "--advertise-exit-node")
	Blank()
	R("tailscale", "status")
	Blank()
	raw, rc := shx.OutputRaw(io.Discard, "tailscale", "ip", "-4")
	Echo("This host Tailscale IPv4: " + shx.OrEcho(raw, rc, "(not logged in yet)"))
	Echo("Admin DNS next: https://login.tailscale.com/admin/dns")
	Echo("  Global nameserver = that 100.x address")
	Echo("  Enable Override local DNS")
	return 0
}

func main() { shx.Main(run) }
