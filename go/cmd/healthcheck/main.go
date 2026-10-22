// healthcheck: periodic Pi-hole + Unbound health check with rate-limited
// desktop notify. Go port of automation/healthcheck.sh (same log lines,
// state/health.json, state/health-notify.json, notify-send and exit code).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

var (
	reBad  = regexp.MustCompile(`(?i)unhealthy|Exit|exited|created|dead`)
	reGood = regexp.MustCompile(`(?i)Up|running|healthy`)
	reNum  = regexp.MustCompile(`^[0-9]+$`)
)

// ContainerIssues mirrors the compose ps grep checks for pihole + unbound.
func ContainerIssues(psOut string) []string {
	var issues []string
	lines := strings.Split(psOut, "\n")
	for _, svc := range []string{"pihole", "unbound"} {
		re := regexp.MustCompile(`(^|[[:space:]])` + svc + `([[:space:]]|$)`)
		line, found := "", false
		for _, l := range lines {
			if re.MatchString(l) {
				line, found = l, true
				break
			}
		}
		switch {
		case !found:
			issues = append(issues, svc+"_missing")
		case reBad.MatchString(line):
			issues = append(issues, svc+"_unhealthy")
		case !reGood.MatchString(line):
			issues = append(issues, svc+"_not_running")
		}
	}
	return issues
}

// WatchdogMode mirrors python3 -c '...get("mode","unknown")' || echo unknown.
func WatchdogMode(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	v, err := py.Decode(data)
	if err != nil {
		return "unknown"
	}
	m, ok := v.(*py.Map)
	if !ok {
		return "unknown"
	}
	return py.Str(m.GetOr("mode", "unknown"))
}

var isoLayouts = []string{"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05.999999Z07:00", "2006-01-02T15:04:05",
	"2006-01-02T15:04:05.999999", "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02"}

// ShouldNotify mirrors the eval'd python: 0 only when the same issue hash
// was notified less than 2h ago.
func ShouldNotify(path, want string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	v, err := py.Decode(data)
	if err != nil {
		return true
	}
	d, ok := v.(*py.Map)
	if !ok {
		return true
	}
	prevHash := d.GetOr("hash", "")
	prevTS := d.GetOr("ts", "")
	age := 999999
	if py.Truthy(prevTS) {
		s, ok := prevTS.(string)
		if !ok {
			return true
		}
		var t time.Time
		parsed := false
		for _, l := range isoLayouts {
			if x, err := time.Parse(l, s); err == nil {
				t, parsed = x, true
				break
			}
		}
		if !parsed {
			return true
		}
		age = int(time.Since(t).Seconds())
	}
	ph, _ := prevHash.(string)
	return !(ph == want && age < 7200)
}

func run() int {
	root := shx.Root()
	logp := root + "/logs/healthcheck.log"
	stateDir := root + "/state"
	healthJSON := stateDir + "/health.json"
	notifyJSON := stateDir + "/health-notify.json"
	shx.MkdirP(root+"/logs", stateDir)
	shx.RedirectToLog(logp)

	var issues []string
	ok := true
	fmt.Printf("[%s] healthcheck start\n", shx.DateISO())

	psOut, _ := shx.DockerOut(io.Discard, "compose", "-f", root+"/docker-compose.yml", "-f", root+"/docker-compose.tailscale.yml", "--env-file", root+"/.env", "ps")
	if ci := ContainerIssues(psOut); len(ci) > 0 {
		issues = append(issues, ci...)
		ok = false
	}

	gravity := "0"
	q := "SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';"
	if raw, rc := shx.DockerOut(io.Discard, "exec", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", q); rc == 0 {
		g := strings.ReplaceAll(raw, "\r", "")
		g, _, _ = strings.Cut(g, "\n")
		gravity = g
	} else if shx.IsFile(root + "/etc-pihole/gravity.db") {
		raw, rc := shx.OutputRaw(io.Discard, "sqlite3", root+"/etc-pihole/gravity.db", q)
		gravity = shx.OrEcho(raw, rc, "0")
	}
	if gravity == "" {
		gravity = "0"
	}
	if !reNum.MatchString(gravity) {
		gravity = "0"
	}
	if g := shx.BashInt(gravity); g < 100000 {
		if g == 0 {
			issues = append(issues, "gravity_missing_or_zero")
		} else {
			issues = append(issues, "gravity_low:"+gravity)
		}
		ok = false
	}

	mode := "unknown"
	if shx.IsFile(stateDir + "/watchdog.json") {
		mode = WatchdogMode(stateDir + "/watchdog.json")
		if mode == "cloudflare" {
			issues = append(issues, "watchdog_cloudflare")
			ok = false
		}
	} else {
		issues = append(issues, "watchdog_state_missing")
		ok = false
	}

	avail := shx.DfAvailKB(root)
	if avail == "" || shx.BashInt(avail) < 8388608 {
		if avail == "" {
			avail = "0"
		}
		issues = append(issues, "disk_low:"+avail+"KB")
		ok = false
	}

	if shx.DockerQuiet("exec", "unbound", "drill-hc", "@127.0.0.1", "dnssec.works") != 0 &&
		shx.DockerQuiet("exec", "unbound", "drill", "@127.0.0.1", "dnssec.works") != 0 {
		issues = append(issues, "unbound_dnssec_fail")
		ok = false
	}

	if shx.Quiet("curl", "-fsS", "--max-time", "5", "http://127.0.0.1/admin/") != 0 {
		issues = append(issues, "admin_ui_unreachable")
		ok = false
	}

	issueList := make([]any, len(issues))
	for i, s := range issues {
		issueList[i] = s
	}
	issuesJSON := "[]"
	if len(issues) > 0 {
		issuesJSON = py.Dumps(issueList, false)
	}
	okStr := "false"
	if ok {
		okStr = "true"
	}
	var gnum int64
	fmt.Sscan(gravity, &gnum)
	data := py.O("ok", ok, "ts", shx.DateISO(), "gravity", gnum, "mode", mode, "issues", issueList)
	if err := os.WriteFile(healthJSON, []byte(py.Dumps(data, true)), 0o666); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(py.Dumps(data, false))
	fmt.Printf("[%s] healthcheck done ok=%s gravity=%s mode=%s issues=%s\n", shx.DateISO(), okStr, gravity, mode, issuesJSON)

	if len(issues) > 0 {
		h := sha256.Sum256([]byte(strings.Join(issues, "\n") + "\n"))
		hash := hex.EncodeToString(h[:])
		should := true
		if shx.IsFile(notifyJSON) {
			should = ShouldNotify(notifyJSON, hash)
		}
		if !should {
			fmt.Printf("[%s] notify suppressed (same issues within 2h)\n", shx.DateISO())
		} else {
			body := strings.Join(issues, "; ")
			shx.Notify("Pi-hole healthcheck", body)
			nd := py.O("hash", hash, "ts", shx.DateISO(), "issues", issueList)
			if err := os.WriteFile(notifyJSON, []byte(py.Dumps(nd, false)), 0o666); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Printf("[%s] notified: %s\n", shx.DateISO(), body)
		}
	}
	if ok {
		return 0
	}
	return 1
}

func main() { shx.Main(run) }

var _ = filepath.Join
