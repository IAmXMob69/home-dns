package shx

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var plainArg = regexp.MustCompile(`^[A-Za-z0-9_./=:,+@%^-]+$`)

// QuoteQ approximates bash printf %q.
func QuoteQ(s string) string {
	if s == "" {
		return "''"
	}
	if plainArg.MatchString(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "$'" + strings.NewReplacer("\\", "\\\\", "'", "\\'", "\n", "\\n", "\t", "\\t", "\r", "\\r").Replace(s) + "'"
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./=:,+@%^-", r) || r > 0x7f) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Docker mirrors lib/docker_cmd.sh: direct docker, then newgrp docker,
// then passwordless sudo; never prompts.
func Docker(c Cmd, args ...string) int {
	if Quiet("docker", "info") == 0 {
		c.Argv = append([]string{"docker"}, args...)
		return c.Run()
	}
	user, _ := Output(io.Discard, "id", "-un")
	members := ""
	if out, rc := Output(io.Discard, "getent", "group", "docker"); rc == 0 {
		f := strings.Split(strings.SplitN(out, "\n", 2)[0], ":")
		if len(f) >= 4 {
			members = f[3]
		}
	}
	if st, err := os.Stat("/usr/bin/newgrp"); err == nil && st.Mode()&0o111 != 0 && strings.Contains(","+members+",", ","+user+",") {
		runner := MustTemp("")
		var b strings.Builder
		b.WriteString("#!/bin/bash\nexec docker ")
		for _, a := range args {
			b.WriteString(QuoteQ(a) + " ")
		}
		b.WriteString("\n")
		os.WriteFile(runner, []byte(b.String()), 0o600)
		os.Chmod(runner, 0o700)
		c.Argv = []string{"/usr/bin/newgrp", "docker"}
		c.Stdin = strings.NewReader("exec /bin/bash --norc --noprofile \"" + runner + "\"\n")
		st := c.Run()
		os.Remove(runner)
		return st
	}
	if Quiet("sudo", "-n", "true") == 0 {
		c.Argv = append([]string{"sudo", "-n", "docker"}, args...)
		return c.Run()
	}
	w := c.Stderr
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintln(w, "docker_cmd: docker unavailable (no active docker group, no passwordless sudo)")
	return 1
}

// DockerOut mirrors "$(docker_cmd ...)" with stderr sent to errw.
func DockerOut(errw io.Writer, args ...string) (string, int) {
	var out bytes.Buffer
	rc := Docker(Cmd{Stdout: &out, Stderr: errw}, args...)
	return strings.TrimRight(out.String(), "\n"), rc
}

// DockerQuiet mirrors docker_cmd ... >/dev/null 2>&1.
func DockerQuiet(args ...string) int {
	return Docker(Cmd{Stdout: io.Discard, Stderr: io.Discard}, args...)
}

// MustDocker mirrors a bare docker_cmd line under set -e.
func MustDocker(args ...string) {
	if rc := Docker(Cmd{}, args...); rc != 0 {
		Fail(rc)
	}
}

// SessionBus is $DBUS_SESSION_BUS_ADDRESS, else this user's bus socket.
func SessionBus() string {
	if v := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); v != "" {
		return v
	}
	return fmt.Sprintf("unix:path=/run/user/%d/bus", os.Getuid())
}

// Notify mirrors DISPLAY=:0.0 DBUS_SESSION_BUS_ADDRESS=... notify-send -a Pi-hole T B >/dev/null 2>&1 || true.
func Notify(title, body string) {
	env := append(os.Environ(), "DISPLAY=:0.0", "DBUS_SESSION_BUS_ADDRESS="+SessionBus())
	Cmd{Argv: []string{"notify-send", "-a", "Pi-hole", title, body}, Env: env, Stdout: io.Discard, Stderr: io.Discard}.Run()
}

// DfAvailKB mirrors df -Pk PATH | awk 'NR==2{print $4}' ("" on failure).
func DfAvailKB(p string) string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return ""
	}
	return fmt.Sprint(uint64(st.Bavail) * uint64(st.Frsize) / 1024)
}

// LsT mirrors ls -1t on a glob: newest first, ties by name.
func LsT(pattern string) []string {
	m, _ := globSorted(pattern)
	type fi struct {
		p string
		t int64
	}
	var xs []fi
	for _, p := range m {
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		xs = append(xs, fi{p, st.ModTime().UnixNano()})
	}
	sort.SliceStable(xs, func(i, j int) bool {
		if xs[i].t != xs[j].t {
			return xs[i].t > xs[j].t
		}
		return xs[i].p < xs[j].p
	})
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.p
	}
	return out
}

// FirstLine mirrors ${v//$'\r'/}; ${v%%$'\n'*}; ${v:-def}.
func FirstLine(v, def string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v, _, _ = strings.Cut(v, "\n")
	if v == "" {
		return def
	}
	return v
}

// Line mirrors printf '%s\n' "$v" | sed -n 'Np' (1-based), \r removed, default.
func Line(v string, n int, def string) string {
	ls := strings.Split(v, "\n")
	s := ""
	if n-1 < len(ls) {
		s = ls[n-1]
	}
	s = strings.ReplaceAll(s, "\r", "")
	if s == "" {
		return def
	}
	return s
}

// BashInt mirrors how [[ x -lt n ]] reads a decimal word (non-numeric -> 0).
func BashInt(s string) int64 {
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
		return 0
	}
	return n
}

// TailLines mirrors tail -n N FILE.
func TailLines(data []byte, n int) []byte {
	if n <= 0 || len(data) == 0 {
		return nil
	}
	end := len(data)
	if data[end-1] == '\n' {
		end--
	}
	i := end
	for c := 0; i > 0; i-- {
		if data[i-1] == '\n' {
			c++
			if c == n {
				break
			}
		}
	}
	return data[i:]
}

// OutputTrim runs c capturing stdout like "$(...)".
func (c Cmd) OutputTrim() (string, int) {
	var out bytes.Buffer
	c.Stdout = &out
	rc := c.Run()
	return strings.TrimRight(out.String(), "\n"), rc
}

// OrEcho mirrors "$(cmd || echo S)": the failed command's partial stdout
// (raw, untrimmed) followed by S, trailing newlines stripped.
func OrEcho(raw string, rc int, s string) string {
	if rc != 0 {
		raw += s + "\n"
	}
	return strings.TrimRight(raw, "\n")
}

// OutputRaw is Output without trimming.
func OutputRaw(stderr io.Writer, argv ...string) (string, int) {
	var out bytes.Buffer
	rc := Cmd{Argv: argv, Stdout: &out, Stderr: stderr}.Run()
	return out.String(), rc
}

// DockerOutRaw is DockerOut without trimming.
func DockerOutRaw(errw io.Writer, args ...string) (string, int) {
	var out bytes.Buffer
	rc := Docker(Cmd{Stdout: &out, Stderr: errw}, args...)
	return out.String(), rc
}
