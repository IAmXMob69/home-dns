// Package shx holds the shared plumbing for Go ports of the stack's bash
// scripts: root discovery, set -e style exits, docker_cmd, date formats,
// log redirection and bash-like temp files.
package shx

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Root is PIHOLE_ROOT (set by the .sh shim), else two levels above the
// binary (<root>/go/bin -> <root>), else $HOME/pihole.
func Root() string {
	if r := os.Getenv("PIHOLE_ROOT"); r != "" {
		return r
	}
	if exe, err := os.Executable(); err == nil {
		r := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
		if _, err := os.Stat(filepath.Join(r, "docker-compose.yml")); err == nil {
			return r
		}
	}
	return filepath.Join(os.Getenv("HOME"), "pihole")
}

// Argv0 is the original script path ($0) passed by the shim.
func Argv0(def string) string {
	if v := os.Getenv("PIHOLE_ARGV0"); v != "" {
		return v
	}
	return def
}

// EnvOr mirrors ${K:-def}.
func EnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Exit is a set -e style abort carrying the exit status.
type Exit struct{ Code int }

func (e Exit) Error() string { return fmt.Sprintf("exit %d", e.Code) }

// Main runs f and turns a panic(Exit) or returned code into os.Exit.
func Main(f func() int) {
	code := 0
	func() {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(Exit); ok {
					code = e.Code
					return
				}
				panic(r)
			}
		}()
		code = f()
	}()
	runAtExit()
	os.Exit(code)
}

var atExit []func()

// Trap registers an EXIT trap; returns a func that clears it (trap - EXIT).
func Trap(f func()) func() {
	atExit = append(atExit, f)
	i := len(atExit) - 1
	return func() { atExit[i] = nil }
}

func runAtExit() {
	for i := len(atExit) - 1; i >= 0; i-- {
		if atExit[i] != nil {
			atExit[i]()
		}
	}
}

// Fail aborts like set -e with the given status.
func Fail(code int) { panic(Exit{code}) }

// Die prints "prefix: msg" to stderr and exits 1.
func Die(prefix, format string, a ...any) {
	fmt.Fprintf(os.Stderr, prefix+": "+format+"\n", a...)
	Fail(1)
}

// Cmd describes one external command.
type Cmd struct {
	Argv   []string
	Stdin  io.Reader
	Stdout io.Writer // nil = inherit
	Stderr io.Writer // nil = inherit
	Env    []string
	Dir    string
}

// Run returns the exit status (127 when not found, like bash).
func (c Cmd) Run() int {
	cmd := exec.Command(c.Argv[0], c.Argv[1:]...)
	cmd.Stdin = c.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout, cmd.Stderr = c.Stdout, c.Stderr
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	cmd.Env, cmd.Dir = c.Env, c.Dir
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	case errors.Is(err, exec.ErrNotFound):
		fmt.Fprintf(cmd.Stderr, "%s: line 1: %s: command not found\n", "bash", c.Argv[0])
		return 127
	default:
		fmt.Fprintln(cmd.Stderr, err)
		return 126
	}
}

// Run runs argv inheriting stdio.
func Run(argv ...string) int { return Cmd{Argv: argv}.Run() }

// Quiet runs argv with stdout and stderr discarded.
func Quiet(argv ...string) int { return Cmd{Argv: argv, Stdout: io.Discard, Stderr: io.Discard}.Run() }

// Must runs argv and aborts (set -e) on non-zero.
func Must(argv ...string) {
	if rc := Run(argv...); rc != 0 {
		Fail(rc)
	}
}

// Output mirrors "$(cmd)": stdout with trailing newlines trimmed.
func Output(stderr io.Writer, argv ...string) (string, int) {
	var out bytes.Buffer
	rc := Cmd{Argv: argv, Stdout: &out, Stderr: stderr}.Run()
	return strings.TrimRight(out.String(), "\n"), rc
}

// RedirectToLog mirrors exec >>LOG 2>&1 (children inherit it too).
func RedirectToLog(path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		Fail(1)
	}
	_ = syscall.Dup3(int(f.Fd()), 1, 0)
	_ = syscall.Dup3(int(f.Fd()), 2, 0)
}

// Date mirrors `date` with no args for the C and en_US locales; any other
// locale shells out to date(1) so the text stays identical.
func Date() string {
	loc := os.Getenv("LC_ALL")
	if loc == "" {
		loc = os.Getenv("LC_TIME")
	}
	if loc == "" {
		loc = os.Getenv("LANG")
	}
	now := time.Now()
	switch {
	case strings.HasPrefix(loc, "en_US"):
		return now.Format("Mon Jan _2 03:04:05 PM MST 2006")
	case loc == "" || loc == "C" || loc == "POSIX" || strings.HasPrefix(loc, "C."):
		return now.Format("Mon Jan _2 15:04:05 MST 2006")
	}
	s, _ := Output(io.Discard, "date")
	return s
}

// DateISO mirrors date -Iseconds.
func DateISO() string { return time.Now().Format("2006-01-02T15:04:05-07:00") }

const tmpChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// MkTemp mirrors mktemp TEMPLATE (last run of X's replaced, mode 0600).
// An empty template means mktemp with no args ($TMPDIR/tmp.XXXXXXXXXX).
func MkTemp(template string) (string, error) {
	if template == "" {
		template = filepath.Join(EnvOr("TMPDIR", "/tmp"), "tmp.XXXXXXXXXX")
	}
	end := strings.LastIndex(template, "XXX")
	if end < 0 {
		return "", fmt.Errorf("mktemp: too few X's in template '%s'", template)
	}
	end += 3
	start := end - 3
	for start > 0 && template[start-1] == 'X' {
		start--
	}
	for i := 0; i < 100; i++ {
		b := make([]byte, end-start)
		_, _ = rand.Read(b)
		for j := range b {
			b[j] = tmpChars[int(b[j])%len(tmpChars)]
		}
		p := template[:start] + string(b) + template[end:]
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("mktemp: failed to create file via template '%s': %s", template, errText(err))
		}
	}
	return "", fmt.Errorf("mktemp: failed to create file via template '%s'", template)
}

// MustTemp is MkTemp that aborts like set -e.
func MustTemp(template string) string {
	p, err := MkTemp(template)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		Fail(1)
	}
	return p
}

func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	s := err.Error()
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// MkdirP mirrors mkdir -p (aborts on failure).
func MkdirP(dirs ...string) {
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: cannot create directory '%s': %s\n", d, errText(err))
			Fail(1)
		}
	}
}

// Chmod mirrors chmod MODE PATH (aborts on failure like set -e).
func Chmod(mode os.FileMode, p string) {
	if err := os.Chmod(p, mode); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "chmod: cannot access '%s': No such file or directory\n", p)
		} else {
			fmt.Fprintf(os.Stderr, "chmod: changing permissions of '%s': %s\n", p, errText(err))
		}
		Fail(1)
	}
}

// MvF mirrors mv -f SRC DST (aborts on failure).
func MvF(src, dst string) {
	if err := os.Rename(src, dst); err != nil {
		if rc := Run("mv", "-f", src, dst); rc != 0 {
			Fail(rc)
		}
	}
}

// NonEmpty mirrors [[ -s path ]].
func NonEmpty(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Size() > 0
}

// IsFile mirrors [[ -f path ]].
func IsFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// UID mirrors $(id -u): it runs id(1) from PATH like the scripts do, so
// stand-in tests behave the same; falls back to geteuid.
func UID() int {
	out, rc := Output(io.Discard, "id", "-u")
	if rc == 0 {
		var n int
		if _, err := fmt.Sscanf(out, "%d", &n); err == nil {
			return n
		}
	}
	return os.Geteuid()
}
