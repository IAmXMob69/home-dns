// watchdog: fail over this PC to Cloudflare if Pi-hole stops answering; fail
// back when it recovers. Go port of watchdog.py (same state file,
// JSON log lines, nmcli/resolvectl/docker calls and exit code).
//
// Also self-heals once per incident via `docker restart pihole` after 2
// consecutive loopback failures, and logs structured events + desktop
// notifications.
//
// Test-only overrides (unset in production): PIHOLE_WATCHDOG_ROOT,
// PIHOLE_WATCHDOG_PIHOLE, PIHOLE_WATCHDOG_LAN, PIHOLE_WATCHDOG_HEAL_WAIT.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pihole/go/internal/conf"
	"pihole/go/internal/dnswire"
	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

const (
	strikes         = 3
	healAfter       = 2
	healCooldownSec = 600
)

var (
	cloudflare  = []string{"1.1.1.1#cloudflare-dns.com", "8.8.8.8#dns.google"}
	root        = envOr("PIHOLE_WATCHDOG_ROOT", shx.Root())
	statePath   = filepath.Join(root, "state", "watchdog.json")
	logPath     = filepath.Join(root, "logs", "watchdog.log")
	pihole      = envOr("PIHOLE_WATCHDOG_PIHOLE", "127.0.0.1")
	lanDNS      = envOr("PIHOLE_WATCHDOG_LAN", "")
	healWaitSec = 8

	// Set from WIFI_CON, WIFI_DEV and DOT_AUTH_NAME (or PIHOLE_DNS) in run.
	wifiCon, wifiDev, piholeDNS string
)

// loadSettings reads the host settings, exiting with a message if one is
// missing. The LAN probe (LAN_IPV4) is optional and only logged.
func loadSettings() {
	wifiCon = conf.Need("WIFI_CON", conf.HintWifiCon)
	wifiDev = conf.Need("WIFI_DEV", conf.HintWifiDev)
	piholeDNS = conf.Get("PIHOLE_DNS", "")
	if piholeDNS == "" {
		piholeDNS = "127.0.0.1#" + conf.Need("DOT_AUTH_NAME", conf.HintDotName)
	}
	if lanDNS == "" && conf.Set("LAN_IPV4") {
		lanDNS = conf.Get("LAN_IPV4", "")
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isoNow() string { return time.Now().Format("2006-01-02T15:04:05-07:00") }

func dnsOK(server string) bool {
	msg, err := dnswire.BuildQuery("example.com", 1)
	if err != nil {
		return false
	}
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(server, "53"))
	if err != nil {
		return false
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.WriteToUDP(msg, raddr); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return false
	}
	return n >= 12 && (buf[3]&0x0F == 0 || buf[3]&0x0F == 3)
}

// State mirrors the Python dict: loaded values are kept raw.
type State struct{ m *py.Map }

func (s State) get(k string) any    { v, _ := s.m.Get(k); return v }
func (s State) set(k string, v any) { s.m.Set(k, v) }
func (s State) mode() any           { return s.get("mode") }
func (s State) modeIs(m string) bool {
	v, ok := s.get("mode").(string)
	return ok && v == m
}

func defaultState() State {
	return State{py.O("mode", "pihole", "fail", 0, "ok", 0, "last_heal", nil, "last_notify", nil, "heal_tried", false)}
}

func loadState() State {
	data, err := os.ReadFile(statePath)
	if err == nil {
		if v, err := py.Decode(data); err == nil {
			if m, ok := v.(*py.Map); ok {
				return State{m}
			}
		}
	}
	return defaultState()
}

func saveState(s State) {
	_ = os.MkdirAll(filepath.Dir(statePath), 0o777)
	out := py.O(
		"mode", s.m.GetOr("mode", "pihole"),
		"fail", py.ToInt(s.m.GetOr("fail", 0)),
		"ok", py.ToInt(s.m.GetOr("ok", 0)),
		"last_heal", s.get("last_heal"),
		"last_notify", s.get("last_notify"),
		"heal_tried", py.Truthy(s.m.GetOr("heal_tried", false)),
	)
	_ = os.WriteFile(statePath, []byte(py.Dumps(out, false)), 0o666)
}

func logLine(event string, kv ...any) {
	_ = os.MkdirAll(filepath.Dir(logPath), 0o777)
	payload := py.O("ts", isoNow(), "event", event)
	for i := 0; i+1 < len(kv); i += 2 {
		payload.Set(kv[i].(string), kv[i+1])
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(py.Dumps(payload, true) + "\n")
}

// runCmd runs argv with an optional timeout, capturing output. It returns the
// exit code, whether it timed out, and a start error (e.g. not found).
func runCmd(timeout time.Duration, env []string, stdin string, capture bool, argv ...string) (int, bool, error) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if env != nil {
		cmd.Env = env
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if !capture {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), false, nil
	}
	if err != nil {
		return -1, false, err
	}
	return 0, false, nil
}

func pyList(argv []string) string { return py.Repr(argv) }

func notify(title, body string, s State) {
	env := os.Environ()
	env = setEnv(env, "DISPLAY", ":0.0")
	env = setEnv(env, "DBUS_SESSION_BUS_ADDRESS", shx.SessionBus())
	argv := []string{"notify-send", "-a", "Pi-hole", title, body}
	_, timedOut, err := runCmd(10*time.Second, env, "", true, argv...)
	switch {
	case timedOut:
		logLine("notify_error", "error", fmt.Sprintf("Command '%s' timed out after 10 seconds", pyList(argv)), "title", title)
	case err != nil:
		logLine("notify_error", "error", "[Errno 2] No such file or directory: 'notify-send'", "title", title)
	default:
		s.set("last_notify", isoNow())
		logLine("notify", "title", title, "body", body)
	}
}

func setEnv(env []string, k, v string) []string {
	out := env[:0:0]
	for _, e := range env {
		if !strings.HasPrefix(e, k+"=") {
			out = append(out, e)
		}
	}
	return append(out, k+"="+v)
}

func nmcli(args ...string) { runCmd(0, nil, "", true, append([]string{"nmcli"}, args...)...) }

func reapplyOrResolvectl(dns []string) {
	rc, _, err := runCmd(0, nil, "", true, "nmcli", "device", "reapply", wifiDev)
	if err != nil || rc != 0 {
		runCmd(0, nil, "", false, append([]string{"resolvectl", "dns", wifiDev}, dns...)...)
		runCmd(0, nil, "", false, "resolvectl", "dnsovertls", wifiDev, "yes")
	}
}

func usePihole() {
	nmcli("connection", "modify", wifiCon, "ipv4.dns", piholeDNS, "ipv6.dns", "", "connection.dns-over-tls", "yes")
	reapplyOrResolvectl([]string{piholeDNS})
}

func useCloudflare() {
	nmcli("connection", "modify", wifiCon, "ipv4.dns", strings.Join(cloudflare, ","), "connection.dns-over-tls", "yes")
	reapplyOrResolvectl(cloudflare)
}

// dockerRestartPihole mirrors lib/docker_cmd.sh (direct docker, then newgrp, then sudo -n).
func dockerRestartPihole() int {
	if rc, to, err := runCmd(15*time.Second, nil, "", true, "docker", "info"); err == nil && !to && rc == 0 {
		rc, to, err := runCmd(60*time.Second, nil, "", true, "docker", "restart", "pihole")
		if err == nil && !to {
			return rc
		}
	}
	if rc := newgrpRestart(); rc >= 0 {
		return rc
	}
	rc, to, err := runCmd(60*time.Second, nil, "", true, "sudo", "-n", "docker", "restart", "pihole")
	if err != nil || to {
		return 1
	}
	return rc
}

// newgrpRestart returns the exit code, or -1 when the newgrp path is not usable.
func newgrpRestart() int {
	user, err := exec.Command("id", "-un").Output()
	if err != nil {
		return -1
	}
	members, err := exec.Command("getent", "group", "docker").Output()
	if err != nil {
		return -1
	}
	ms := strings.TrimSpace(string(members))
	var list []string
	if ms != "" {
		parts := strings.Split(ms, ":")
		list = strings.Split(parts[len(parts)-1], ",")
	}
	u := strings.TrimSpace(string(user))
	found := false
	for _, m := range list {
		if m == u {
			found = true
		}
	}
	if st, err := os.Stat("/usr/bin/newgrp"); !found || err != nil || !st.Mode().IsRegular() {
		return -1
	}
	runner := fmt.Sprintf("/tmp/pihole-watchdog-docker-%d.sh", os.Getpid())
	if err := os.WriteFile(runner, []byte("#!/bin/bash\nexec docker restart pihole\n"), 0o700); err != nil {
		return -1
	}
	defer os.Remove(runner)
	_ = os.Chmod(runner, 0o700)
	rc, to, err := runCmd(90*time.Second, nil, fmt.Sprintf("exec /bin/bash --norc --noprofile \"%s\"\n", runner), true, "/usr/bin/newgrp", "docker")
	if err != nil || to {
		return -1
	}
	return rc
}

var isoLayouts = []string{
	"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05.999999Z07:00", "2006-01-02T15:04:05",
	"2006-01-02T15:04:05.999999", "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05",
	"2006-01-02T15:04Z07:00", "2006-01-02T15:04", "2006-01-02",
}

func parseISO(s string) (time.Time, error) {
	for _, l := range isoLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil // naive layouts parse as UTC, like replace(tzinfo=utc)
		}
	}
	return time.Time{}, fmt.Errorf("Invalid isoformat string: %s", py.Repr(s))
}

func healCooldownOK(s State) bool {
	last := s.get("last_heal")
	if !py.Truthy(last) {
		return true
	}
	then, err := parseISO(py.Str(last))
	if err != nil {
		return true
	}
	return time.Since(then).Seconds() >= healCooldownSec
}

func trySelfHeal(s State) bool {
	if !healCooldownOK(s) {
		logLine("heal_skipped_cooldown", "fail", s.get("fail"), "last_heal", s.get("last_heal"))
		s.set("heal_tried", true)
		return false
	}
	logLine("heal_attempt", "fail", s.get("fail"), "mode", s.mode())
	rc := dockerRestartPihole()
	s.set("last_heal", isoNow())
	s.set("heal_tried", true)
	time.Sleep(time.Duration(healWaitSec) * time.Second)
	recovered := dnsOK(pihole)
	logLine("heal_result", "docker_rc", rc, "recovered", recovered)
	return recovered
}

func run() int {
	loadSettings()
	if v, err := strconv.Atoi(os.Getenv("PIHOLE_WATCHDOG_HEAL_WAIT")); err == nil {
		healWaitSec = v
	}
	s := loadState()
	loopbackOK := dnsOK(pihole)
	lanOK := lanDNS != "" && dnsOK(lanDNS)
	healthy := loopbackOK
	lanAlive := loopbackOK || lanOK

	logLine("check", "mode", s.mode(), "loopback", loopbackOK, "lan", lanOK, "lan_alive", lanAlive,
		"fail", py.ToInt(s.m.GetOr("fail", 0)), "ok", py.ToInt(s.m.GetOr("ok", 0)))

	if healthy {
		s.set("fail", 0)
		s.set("heal_tried", false)
		ok := py.ToInt(s.m.GetOr("ok", 0)) + 1
		s.set("ok", ok)
		if !s.modeIs("pihole") && ok >= strikes {
			usePihole()
			s.set("mode", "pihole")
			msg := "Pi-hole recovered; DNS restored to 127.0.0.1"
			fmt.Println(msg)
			logLine("recovery", "fail", 0, "ok", ok)
			notify("Pi-hole recovered", msg, s)
		}
	} else {
		s.set("ok", 0)
		fail := py.ToInt(s.m.GetOr("fail", 0)) + 1
		s.set("fail", fail)
		if s.modeIs("pihole") && fail >= healAfter && !py.Truthy(s.get("heal_tried")) {
			if trySelfHeal(s) {
				s.set("fail", 0)
				s.set("ok", 1)
				s.set("heal_tried", false)
				logLine("heal_success", "fail", fail)
				saveState(s)
				return 0
			}
			fail = py.ToInt(s.get("fail"))
		}
		if !s.modeIs("cloudflare") && fail >= strikes {
			useCloudflare()
			s.set("mode", "cloudflare")
			msg := "Pi-hole down; failed over to 1.1.1.1+8.8.8.8"
			fmt.Fprintln(os.Stderr, msg)
			logLine("failover", "fail", fail, "lan_ok", lanOK)
			notify("Pi-hole failover", msg, s)
		}
	}
	saveState(s)
	// Always succeed: this is a probe/failover actor, not a healthcheck.
	return 0
}

func main() { os.Exit(run()) }

var _ = json.Number("")
