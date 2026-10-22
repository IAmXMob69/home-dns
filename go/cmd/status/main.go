// status: print the Pi-hole automation status for this Docker host.
// Go port of automation/status.sh (same sections, order and fallbacks).
package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"

	"pihole/go/internal/shx"
)

func cstr(b [65]int8) string {
	var s []byte
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

func catOr(p, missing string) {
	if shx.IsFile(p) {
		data, _ := os.ReadFile(p)
		os.Stdout.Write(data)
		fmt.Println()
	} else {
		fmt.Println(missing)
	}
}

func tail(p string, n int) {
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tail: cannot open '%s' for reading: No such file or directory\n", p)
		return
	}
	os.Stdout.Write(shx.TailLines(data, n))
}

func adlists() string {
	con, err := sql.Open("sqlite", "file:"+shx.Root()+"/etc-pihole/gravity.db")
	if err != nil {
		return ""
	}
	defer con.Close()
	var n int64
	if err := con.QueryRow("select count(*) from adlist where enabled=1").Scan(&n); err != nil {
		fmt.Fprintf(os.Stderr, "sqlite3.OperationalError: %v\n", err)
		return ""
	}
	return fmt.Sprintf("%d enabled", n)
}

func run() int {
	root := shx.Root()
	p := fmt.Println
	p("===============================")
	p(" Pi-hole automation status")
	p("===============================")
	p()
	var u syscall.Utsname
	syscall.Uname(&u)
	p("Host: " + cstr(u.Sysname) + " " + cstr(u.Release) + " " + cstr(u.Machine))
	p("Pi-hole dir: " + root)
	p()
	p("Containers:")
	if shx.Docker(shx.Cmd{Stderr: io.Discard}, "compose", "-f", root+"/docker-compose.yml", "-f", root+"/docker-compose.tailscale.yml", "--env-file", root+"/.env", "ps") != 0 &&
		(shx.Cmd{Argv: []string{"docker", "compose", "-f", root + "/docker-compose.yml", "ps"}, Stderr: io.Discard}).Run() != 0 {
		p("(docker not available in this session)")
	}
	p()
	p("Pi-hole version (container):")
	if shx.Docker(shx.Cmd{Stderr: io.Discard}, "exec", "pihole", "pihole", "-v") != 0 &&
		(shx.Cmd{Argv: []string{"docker", "exec", "pihole", "pihole", "-v"}, Stderr: io.Discard}).Run() != 0 {
		p("(cannot exec pihole)")
	}
	p()
	p("Watchdog state:")
	catOr(root+"/state/watchdog.json", "(missing)")
	p()
	p("Health state:")
	catOr(root+"/state/health.json", "(missing — run healthcheck.sh)")
	p()
	p("Last gravity:")
	q := "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';"
	if shx.IsFile(root + "/state/last-gravity.json") {
		catOr(root+"/state/last-gravity.json", "")
	} else {
		raw, rc := shx.OutputRaw(io.Discard, "sqlite3", root+"/etc-pihole/gravity.db", q)
		g := shx.OrEcho(raw, rc, "?")
		p("gravity_count=" + g + " (no last-gravity.json yet)")
	}
	p()
	p("gravity_count (live):")
	if (shx.Cmd{Argv: []string{"sqlite3", root + "/etc-pihole/gravity.db", q}, Stderr: io.Discard}).Run() != 0 &&
		shx.Docker(shx.Cmd{Stderr: io.Discard}, "exec", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", q) != 0 {
		p("(unavailable)")
	}
	p()
	p("Timers (pihole-*):")
	if (shx.Cmd{Argv: []string{"systemctl", "--user", "list-timers", "pihole-*", "--no-pager"}, Stderr: io.Discard}).Run() != 0 {
		out, _ := shx.Output(io.Discard, "systemctl", "--user", "list-timers", "--no-pager")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "pihole") {
				p(l)
			}
		}
	}
	p()
	p("cleanup.log (tail):")
	if shx.IsFile(root + "/logs/cleanup.log") {
		tail(root+"/logs/cleanup.log", 15)
	} else {
		p("not created yet")
	}
	p()
	p("Logs:")
	for _, l := range []string{"update-gravity.log", "update-pihole.log", "healthcheck.log", "watchdog.log"} {
		lp := root + "/logs/" + l
		p()
		p("==> " + lp)
		if shx.IsFile(lp) {
			tail(lp, 8)
		} else {
			p("not created yet")
		}
	}
	p()
	p("Adlists: " + adlists())
	return 0
}

func main() { shx.Main(run) }
