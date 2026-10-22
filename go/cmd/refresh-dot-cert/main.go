// refresh-dot-cert: refresh the Tailscale Let's Encrypt cert used by
// dnsdist (DoT/DoH). Go port of scripts/refresh-dot-cert.sh.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"pihole/go/internal/shx"
)

func run() int {
	root := shx.Root()
	name := shx.EnvOr("DOT_AUTH_NAME", "your-host.your-tailnet.ts.net")
	if name == "your-host.your-tailnet.ts.net" {
		fmt.Fprintln(os.Stderr, "Set DOT_AUTH_NAME to this node's MagicDNS name (tailscale status --self).")
		return 1
	}
	cert := root + "/dnsdist/tls.pem"
	key := root + "/dnsdist/tls.key"
	syscall.Umask(0o077)
	shx.MkdirP(root + "/dnsdist")

	tmpCert := shx.MustTemp(root + "/dnsdist/.tls.pem.XXXXXX")
	tmpKey := shx.MustTemp(root + "/dnsdist/.tls.key.XXXXXX")
	clear := shx.Trap(func() { os.Remove(tmpCert); os.Remove(tmpKey) })
	if shx.Run("tailscale", "cert", "--cert-file", tmpCert, "--key-file", tmpKey, name) != 0 {
		fmt.Fprintf(os.Stderr, "tailscale cert failed; leaving existing %s\n", cert)
		return 1
	}
	shx.Chmod(0o644, tmpCert)
	shx.Chmod(0o600, tmpKey)
	shx.MvF(tmpCert, cert)
	shx.MvF(tmpKey, key)
	clear()
	shx.Must("docker", "run", "--rm", "--network", "none", "--user", "0", "--entrypoint", "/bin/sh",
		"-v", root+"/dnsdist:/k", "powerdns/dnsdist-19:latest",
		"-c", "chown 953:953 /k/tls.key && chmod 600 /k/tls.key")

	out, _ := shx.Cmd{Argv: []string{"docker", "compose", "ps", "--status", "running", "--services"}, Dir: root, Stderr: io.Discard}.OutputTrim()
	for _, l := range strings.Split(out, "\n") {
		if l == "dnsdist" {
			if rc := (shx.Cmd{Argv: []string{"docker", "compose", "restart", "dnsdist"}, Dir: root}).Run(); rc != 0 {
				return rc
			}
			break
		}
	}
	fmt.Printf("Refreshed DoT/DoH cert for %s\n", name)
	return 0
}

func main() { shx.Main(run) }
