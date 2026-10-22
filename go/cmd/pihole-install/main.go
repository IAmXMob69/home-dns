// pihole-install: fresh host or recreate: copy CA bundle, DoT cert, start
// the DNS chain. Go port of install.sh (binary renamed so it cannot be
// confused with install(1)). Geolock text is printed verbatim; geolock
// itself is not touched.
package main

import (
	"os"
	"syscall"

	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

func run() int {
	root := shx.Root()
	if err := os.Chdir(root); err != nil {
		return 1
	}
	if !shx.IsFile(".env") {
		M("cp", ".env.example", ".env")
		Echo("Wrote .env from .env.example — edit LAN_IPV4 / passwords before relying on this.")
	}
	ca := ""
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/cert.pem",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ca-certificates/extracted/tls-ca-bundle.pem",
	} {
		if Access(p, 4) {
			ca = p
			break
		}
	}
	if ca == "" {
		Err("No host CA bundle found")
		return 1
	}
	M("cp", ca, root+"/unbound/ca-certificates.crt")
	shx.Chmod(0o644, root+"/unbound/ca-certificates.crt")

	if !shx.IsFile("unbound/tls.pem") || !shx.IsFile("unbound/tls.key") {
		M("chmod", "+x", "scripts/gen-dot-cert.sh")
		M("./scripts/gen-dot-cert.sh", "pihole.lan")
	}
	if rc := ChmodAll(0o644, "unbound/tls.pem"); rc != 0 {
		return rc
	}

	// dnsdist (DoT :853 / DoH :8443) wants a cert in dnsdist/. With Tailscale
	// and DOT_AUTH_NAME set it gets a real one; otherwise it reuses the
	// self-signed one.
	shx.MkdirP("dnsdist")
	M("chmod", "+x", "scripts/refresh-dot-cert.sh")
	R("./scripts/refresh-dot-cert.sh")
	if !nonEmpty("dnsdist/tls.pem") || !nonEmpty("dnsdist/tls.key") {
		Echo("Using the self-signed pihole.lan cert for dnsdist.")
		M("cp", "unbound/tls.pem", "dnsdist/tls.pem")
		shx.Chmod(0o644, "dnsdist/tls.pem")
		M("docker", "run", "--rm", "--network", "none", "-v", root+"/unbound:/u:ro", "-v", root+"/dnsdist:/k", "busybox:stable",
			"sh", "-c", "cp /u/tls.key /k/tls.key && chown 953:953 /k/tls.key && chmod 600 /k/tls.key")
	}

	// The DoT key stays 0600 and is owned by Unbound's uid (101:102) so only
	// Unbound can read it. Docker does the chown, so no sudo is needed.
	if st, err := os.Stat("unbound/tls.key"); err != nil || !keyOwned(st) {
		M("docker", "run", "--rm", "--network", "none", "-v", root+"/unbound:/u", "busybox:stable",
			"sh", "-c", "chown 101:102 /u/tls.key && chmod 600 /u/tls.key")
	}

	shx.MkdirP("etc-pihole")
	M(append(append([]string{"chmod", "+x"}, Globs("scripts/*.sh")...), "install.sh")...)
	M("docker", "compose", "up", "-d", "--force-recreate", "dnscrypt", "unbound", "pihole", "dnsdist")
	M("docker", "compose", "ps")
	Blank()
	Echo("Probe Unbound:")
	R("docker", "exec", "unbound", "drill", "@127.0.0.1", "dnssec.works")
	Blank()
	Echo("Geo-lock is off until you:")
	Echo("  cp geolock/settings.env.example geolock/settings.env")
	Echo("  # set GEOLOCK_ENABLED=1")
	Echo("  sudo ./scripts/geolock-apply.sh")
	return 0
}

func nonEmpty(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}

// keyOwned mirrors [[ "$(stat -c '%u:%g %a' unbound/tls.key)" == "101:102 600" ]].
func keyOwned(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 101 && sys.Gid == 102 && st.Mode().Perm() == 0o600
}

func main() { shx.Main(run) }
