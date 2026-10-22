// Package priv holds helpers shared by the Go ports of the privileged
// one-off scripts (install.sh, harden.sh, fix-pihole.sh, ...): the
// lib/dot-dns.sh functions, the PROBE selection and wait loops, and small
// bash/coreutils behaviours those scripts lean on. External tools (nmcli,
// docker, ufw, iptables, pacman, systemctl, chown, install, ln, getent, ss,
// curl, sleep) are still exec'd from PATH exactly as the shell did.
package priv

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"pihole/go/internal/conf"
	"pihole/go/internal/shx"
)

// PiholeDir is the checkout these tools live in (PIHOLE_ROOT from the
// shim, else two levels above the binary).
func PiholeDir() string { return shx.Root() }

// Owner is the login that owns the checkout: PIHOLE_USER, else SUDO_USER.
// It exits with a message when neither is set.
func Owner() string {
	if u := conf.Get("PIHOLE_USER", os.Getenv("SUDO_USER")); u != "" && u != "root" {
		return u
	}
	return conf.Need("PIHOLE_USER", conf.HintUser)
}

// NetLink returns WIFI_CON and WIFI_DEV, or exits explaining them.
func NetLink() (con, dev string) {
	return conf.Need("WIFI_CON", conf.HintWifiCon), conf.Need("WIFI_DEV", conf.HintWifiDev)
}

// Access mirrors bash [[ -x / -r ]] (access(2), so root sees any x bit).
func Access(p string, mode uint32) bool { return syscall.Access(p, mode) == nil }

// Probe mirrors the PROBE=(...) selection.
func Probe(dir string) []string {
	if Access(dir+"/go/bin/dns-probe", 1) {
		return []string{dir + "/go/bin/dns-probe"}
	}
	return []string{"python3", dir + "/dns-probe.py"}
}

// RequireRoot mirrors: if [[ ${EUID} -ne 0 ]]; then echo "Run as: sudo $0" >&2; exit 1; fi
func RequireRoot(defArgv0 string) {
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Run as: sudo %s\n", shx.Argv0(defArgv0))
		shx.Fail(1)
	}
}

// R runs argv inheriting stdio and returns its rc.
func R(argv ...string) int { return shx.Run(argv...) }

// M runs argv and exits with its rc on failure (set -e).
func M(argv ...string) { shx.Must(argv...) }

// Q runs argv with stdout+stderr discarded (>/dev/null 2>&1).
func Q(argv ...string) int { return shx.Quiet(argv...) }

// QOut runs argv with stdout discarded (>/dev/null).
func QOut(argv ...string) int { return shx.Cmd{Argv: argv, Stdout: io.Discard}.Run() }

// QErr runs argv with stderr discarded (2>/dev/null).
func QErr(argv ...string) int { return shx.Cmd{Argv: argv, Stderr: io.Discard}.Run() }

// Sleep execs sleep(1) like the shell does.
func Sleep(arg string) { M("sleep", arg) }

// CommandV mirrors command -v NAME >/dev/null 2>&1.
func CommandV(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Echo prints a line on stdout; Err on stderr.
func Echo(s string) { fmt.Println(s) }
func Err(s string)  { fmt.Fprintln(os.Stderr, s) }
func Blank()        { fmt.Println() }

// CatTo mirrors cat FILE >&w (error text from cat(1) on failure).
func CatTo(w io.Writer, p string) int {
	data, err := os.ReadFile(p)
	if err != nil {
		msg := "No such file or directory"
		if os.IsPermission(err) {
			msg = "Permission denied"
		} else if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EISDIR {
			msg = "Is a directory"
		}
		fmt.Fprintf(os.Stderr, "cat: %s: %s\n", p, msg)
		return 1
	}
	w.Write(data)
	return 0
}

// WaitProbe mirrors
//
//	for _ in $(seq 1 N); do
//	  if "${PROBE[@]}" HOST TARGET >LOG 2>&1; then cat LOG; ready=1; break; fi
//	  sleep S
//	done
func WaitProbe(probe []string, host, target string, n int, s, logPath string) bool {
	for i := 0; i < n; i++ {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
		if err == nil {
			rc := shx.Cmd{Argv: append(append([]string{}, probe...), host, target), Stdout: f, Stderr: f}.Run()
			f.Close()
			if rc == 0 {
				CatTo(os.Stdout, logPath)
				return true
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s: Permission denied\n", logPath)
		}
		Sleep(s)
	}
	return false
}

// ProbeOr mirrors "${PROBE[@]}" HOST TARGET (inherited stdio), returning rc.
func ProbeRC(probe []string, host, target string) int {
	return R(append(append([]string{}, probe...), host, target)...)
}

// GetentHead2 mirrors getent hosts NAME | head -2 under set -e/pipefail.
func GetentHead2(name string) {
	out, rc := shx.OutputRaw(os.Stderr, "getent", "hosts", name)
	lines := strings.SplitAfter(out, "\n")
	for i, l := range lines {
		if i == 2 {
			break
		}
		fmt.Print(l)
	}
	if rc != 0 {
		shx.Fail(rc)
	}
}

// GrepOut mirrors CMD | grep [-E] PATTERN || true (matching lines printed).
func GrepOut(re *regexp.Regexp, argv ...string) {
	out, _ := shx.OutputRaw(os.Stderr, argv...)
	for _, l := range strings.SplitAfter(out, "\n") {
		if l == "" {
			continue
		}
		if re.MatchString(strings.TrimSuffix(l, "\n")) {
			if !strings.HasSuffix(l, "\n") {
				l += "\n"
			}
			fmt.Print(l)
		}
	}
}

// UfwActive mirrors command -v ufw && ufw status | grep -qi 'Status: active'.
func UfwActive() bool {
	if !CommandV("ufw") {
		return false
	}
	out, rc := shx.OutputRaw(os.Stderr, "ufw", "status")
	return rc == 0 && strings.Contains(strings.ToLower(out), "status: active")
}

// Pipe mirrors CMD | grep -q PATTERN (pipefail: CMD must succeed too).
func PipeQ(re *regexp.Regexp, argv ...string) bool {
	out, rc := shx.OutputRaw(os.Stderr, argv...)
	if rc != 0 {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ChmodAll mirrors chmod MODE P... (each path tried; rc 1 if any failed).
func ChmodAll(mode os.FileMode, paths ...string) int {
	rc := 0
	for _, p := range paths {
		if err := os.Chmod(p, mode); err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "chmod: cannot access '%s': No such file or directory\n", p)
			} else {
				fmt.Fprintf(os.Stderr, "chmod: changing permissions of '%s': Operation not permitted\n", p)
			}
			rc = 1
		}
	}
	return rc
}

// Globs expands each pattern like bash (unmatched pattern kept literally).
func Globs(pats ...string) []string {
	var out []string
	for _, p := range pats {
		if strings.ContainsAny(p, "*?[") {
			out = append(out, shx.Glob(p)...)
		} else {
			out = append(out, p)
		}
	}
	return out
}

// WriteHeredoc mirrors cat > FILE <<EOF (truncate, umask perms; bash's
// redirection error and exit 1 on failure).
func WriteHeredoc(argv0, p, body string, line int) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		msg := "No such file or directory"
		if os.IsPermission(err) {
			msg = "Permission denied"
		} else if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EISDIR {
			msg = "Is a directory"
		}
		fmt.Fprintf(os.Stderr, "%s: line %d: %s: %s\n", argv0, line, p, msg)
		shx.Fail(1)
	}
	f.WriteString(body)
	f.Close()
}

// PyReadText mirrors pathlib.Path.read_text() (universal newlines). On
// error it prints a Python-style last line and exits 1 like the crashed
// python3 step under set -e.
func PyReadText(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\nFileNotFoundError: [Errno 2] No such file or directory: '%s'\n", p)
		shx.Fail(1)
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// PyWriteText mirrors pathlib.Path.write_text() (truncate, umask perms).
func PyWriteText(p, s string) {
	if err := os.WriteFile(p, []byte(s), 0o666); err != nil {
		fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\nPermissionError: [Errno 13] Permission denied: '%s'\n", p)
		shx.Fail(1)
	}
}

// UpsertBlock mirrors the "# BEGIN/END pihole-docker-user" python upsert.
func UpsertBlock(p, block string) {
	text := PyReadText(p)
	begin, end := "# BEGIN pihole-docker-user", "# END pihole-docker-user"
	if strings.Contains(text, begin) && strings.Contains(text, end) {
		pre := text[:strings.Index(text, begin)]
		post := text[strings.Index(text, end)+len(end):]
		PyWriteText(p, pre+block+strings.TrimLeft(post, "\n"))
	} else {
		PyWriteText(p, PyRstrip(text)+"\n\n"+block)
	}
}

// PyRstrip mirrors str.rstrip().
func PyRstrip(s string) string {
	return strings.TrimRightFunc(s, func(r rune) bool {
		return r == ' ' || (r >= '\t' && r <= '\r') || (r >= 0x1c && r <= 0x1f) || r == 0x85 || r == 0xa0 ||
			r == 0x1680 || (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
	})
}

// Iptables mirrors: if T -nL DOCKER-USER >/dev/null 2>&1; then T -F ...; T -A ... (set -e); fi
func Iptables(tool string, rules [][]string) {
	if Q(tool, "-nL", "DOCKER-USER") != 0 {
		return
	}
	M(tool, "-F", "DOCKER-USER")
	for _, r := range rules {
		M(append([]string{tool, "-A", "DOCKER-USER"}, r...)...)
	}
}

// SortNR mirrors sort -nr for plain integer lines.
func SortNR(nums []string) {
	sort.SliceStable(nums, func(i, j int) bool { return shx.BashInt(nums[i]) > shx.BashInt(nums[j]) })
}

// DotDNS mirrors lib/dot-dns.sh: settings are read once, up front, so a
// missing one stops the tool before it changes anything.
type DotDNS struct{ PiholeDNS, CloudflareDNS, Con, Dev string }

func NewDotDNS() DotDNS {
	d := DotDNS{CloudflareDNS: conf.Get("CLOUDFLARE_DOT_DNS", "1.1.1.1#cloudflare-dns.com,8.8.8.8#dns.google")}
	d.Con, d.Dev = NetLink()
	d.PiholeDNS = conf.Get("PIHOLE_DNS", "")
	if d.PiholeDNS == "" {
		d.PiholeDNS = "127.0.0.1#" + conf.Need("DOT_AUTH_NAME", conf.HintDotName)
	}
	return d
}

// runSeq executes commands like a bash function body. With errexit a
// failure exits the tool; without (called as `f || true`) it keeps going
// and returns the last command's status.
func runSeq(errexit bool, cmds ...[]string) int {
	rc := 0
	for _, c := range cmds {
		rc = R(c...)
		if rc != 0 && errexit {
			shx.Fail(rc)
		}
	}
	return rc
}

func (d DotDNS) reapply(errexit bool, fallback ...[]string) int {
	if Q("nmcli", "device", "reapply", d.Dev) == 0 {
		return 0
	}
	return runSeq(errexit, fallback...)
}

// FailoverPublic mirrors failover_public_dns.
func (d DotDNS) FailoverPublic(errexit bool) int {
	runSeq(errexit, []string{"nmcli", "connection", "modify", d.Con, "ipv4.dns", d.CloudflareDNS, "connection.dns-over-tls", "yes"})
	return d.reapply(errexit,
		[]string{"resolvectl", "dns", d.Dev, "1.1.1.1#cloudflare-dns.com", "8.8.8.8#dns.google"},
		[]string{"resolvectl", "dnsovertls", d.Dev, "yes"})
}

// RestorePihole mirrors restore_pihole_dns.
func (d DotDNS) RestorePihole(errexit bool) int {
	runSeq(errexit, []string{"nmcli", "connection", "modify", d.Con, "ipv4.dns", d.PiholeDNS, "ipv6.dns", "",
		"ipv4.ignore-auto-dns", "yes", "ipv6.ignore-auto-dns", "yes", "connection.dns-over-tls", "yes"})
	return d.reapply(errexit,
		[]string{"resolvectl", "dns", d.Dev, d.PiholeDNS},
		[]string{"resolvectl", "dnsovertls", d.Dev, "yes"})
}
