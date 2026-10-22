// update-pihole: weekly Docker Pi-hole/Unbound image update. Temporarily
// fails host DNS over to Cloudflare DoT during compose pull/up, waits for
// Pi-hole to answer on 127.0.0.1, then restores Pi-hole DoT. Go port of
// automation/update-pihole.sh + lib/dot-dns.sh (same log, calls, exit codes).
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

func probe(root string) []string {
	if st, err := os.Stat(root + "/go/bin/dns-probe"); err == nil && st.Mode()&0o111 != 0 {
		return []string{root + "/go/bin/dns-probe"}
	}
	return []string{"python3", root + "/dns-probe.py"}
}

func compose(root string, args ...string) int {
	return shx.Docker(shx.Cmd{Dir: root}, append([]string{"compose", "--env-file", ".env", "-f", "docker-compose.yml", "-f", "docker-compose.tailscale.yml"}, args...)...)
}

func run() int {
	root := shx.Root()
	dns := priv.NewDotDNS()
	pr := probe(root)
	shx.MkdirP(root + "/logs")
	shx.RedirectToLog(root + "/logs/update-pihole.log")
	fmt.Printf("[%s] Docker Pi-hole/Unbound image update start\n", shx.Date())
	if err := os.Chdir(root); err != nil {
		return 1
	}
	fmt.Printf("[%s] Temporarily setting Wi-Fi DNS to Cloudflare DoT\n", shx.Date())
	dns.FailoverPublic(true)

	pullRC := compose(root, "pull")
	upRC := compose(root, "up", "-d")
	if pullRC != 0 || upRC != 0 {
		fmt.Printf("[%s] ERROR: compose pull/up failed (pull=%d up=%d); leaving Cloudflare DNS\n", shx.Date(), pullRC, upRC)
		return 1
	}

	fmt.Printf("[%s] Waiting for Pi-hole DNS on 127.0.0.1\n", shx.Date())
	const probeLog = "/tmp/pihole-update-probe.log"
	ready := false
	for i := 0; i < 40; i++ {
		f, err := os.OpenFile(probeLog, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: line 46: %s: Permission denied\n", shx.Argv0(root+"/automation/update-pihole.sh"), probeLog)
		} else {
			rc := shx.Cmd{Argv: append(append([]string{}, pr...), "example.com", "127.0.0.1"), Stdout: f, Stderr: f}.Run()
			f.Close()
			if rc == 0 {
				data, _ := os.ReadFile(probeLog)
				os.Stdout.Write(data)
				ready = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !ready {
		if data, err := os.ReadFile(probeLog); err == nil {
			os.Stderr.Write(data)
		}
		fmt.Printf("[%s] ERROR: Pi-hole did not answer after update; leaving Cloudflare DNS\n", shx.Date())
		return 1
	}
	fmt.Printf("[%s] Restoring Wi-Fi DNS to Pi-hole DoT\n", shx.Date())
	dns.RestorePihole(true)
	fmt.Printf("[%s] SUCCESS: compose pull/up completed; DNS restored to Pi-hole\n", shx.Date())
	if rc := compose(root, "ps"); rc != 0 {
		return rc
	}
	return 0
}

func main() { shx.Main(run) }

var _ = io.Discard
