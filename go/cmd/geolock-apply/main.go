// geolock-apply: install or remove table inet geolock for DNS/DoT using
// ipverse country CIDRs. Go port of scripts/geolock-apply.sh: same args,
// env vars (GEOLOCK_SETTINGS, GEOLOCK_CACHE, GEOLOCK_URL_BASE,
// GEOLOCK_DRY_RUN), messages, exit codes and byte-identical geolock.nft.
// Always accepts loopback, RFC1918, and Tailscale CGNAT (100.64.0.0/10).
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pihole/go/internal/cidr"
	"pihole/go/internal/shx"
)

func die(f string, a ...any) { shx.Die("geolock", f, a...) }

var (
	reSkip   = regexp.MustCompile(`^[[:space:]]*(#|$)`)
	reKV     = regexp.MustCompile(`^[[:space:]]*([A-Z_]+)=["']?([A-Za-z0-9,._-]*)["']?[[:space:]]*$`)
	reBool   = regexp.MustCompile(`^[01]$`)
	reMode   = regexp.MustCompile(`^(allow|deny)$`)
	rePorts  = regexp.MustCompile(`^[0-9]+(,[0-9]+)*$`)
	reNum    = regexp.MustCompile(`^[0-9]+$`)
	reCC     = regexp.MustCompile(`^[a-z]{2}$`)
	reCgroup = regexp.MustCompile(`^[A-Za-z0-9@._:-]+(/[A-Za-z0-9@._:-]+)*$`)
	settings = map[string]string{
		"GEOLOCK_ENABLED": "0", "GEOLOCK_MODE": "allow", "GEOLOCK_ALLOW_COUNTRIES": "US,DE",
		"GEOLOCK_DENY_COUNTRIES": "", "GEOLOCK_PORTS": "53,853", "GEOLOCK_MAX_AGE_DAYS": "7",
	}
)

// readLines mirrors `while IFS= read -r line || [[ -n $line ]]`.
func readLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// ParseSettings applies the safe KEY=VALUE reader to settings.
func ParseSettings(path string, data []byte, set map[string]string, warn io.Writer) error {
	for i, line := range readLines(data) {
		lineno := i + 1
		line = strings.TrimSuffix(line, "\r")
		if reSkip.MatchString(line) {
			continue
		}
		m := reKV.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("%s:%d: expected KEY=value", path, lineno)
		}
		key, val := m[1], m[2]
		switch key {
		case "GEOLOCK_ENABLED":
			if !reBool.MatchString(val) {
				return fmt.Errorf("%s must be 0 or 1", key)
			}
		case "GEOLOCK_MODE":
			if !reMode.MatchString(val) {
				return fmt.Errorf("%s must be allow or deny", key)
			}
		case "GEOLOCK_ALLOW_COUNTRIES", "GEOLOCK_DENY_COUNTRIES":
		case "GEOLOCK_PORTS":
			if !rePorts.MatchString(val) {
				return fmt.Errorf("%s must be like 53,853", key)
			}
		case "GEOLOCK_MAX_AGE_DAYS":
			if !reNum.MatchString(val) {
				return fmt.Errorf("%s must be a number", key)
			}
		default:
			fmt.Fprintf(warn, "geolock: ignoring unknown key %s\n", key)
			continue
		}
		set[key] = val
	}
	return nil
}

// Codes mirrors: for cc in ${raw//,/ }; cc=${cc,,}; validate.
func Codes(raw string) ([]string, error) {
	var codes []string
	for _, cc := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		cc = strings.ToLower(cc)
		if !reCC.MatchString(cc) {
			return nil, fmt.Errorf("bad country code '%s' (use ISO 3166-1 alpha-2)", cc)
		}
		codes = append(codes, cc)
	}
	return codes, nil
}

// sedIndent mirrors sed 's/^/      /; s/$/,/' (keeps a missing final newline missing).
func sedIndent(w *bytes.Buffer, data []byte) {
	if len(data) == 0 {
		return
	}
	lines := bytes.Split(data, []byte("\n"))
	last := len(lines) - 1
	for i, l := range lines {
		if i == last {
			if len(l) == 0 {
				break
			}
			w.WriteString("      ")
			w.Write(l)
			w.WriteString(",")
			break
		}
		w.WriteString("      ")
		w.Write(l)
		w.WriteString(",\n")
	}
}

// Ruleset renders geolock.nft exactly like the shell heredoc of echos.
func Ruleset(mode, ports string, underlay bool, appCg string, lists [][]byte) []byte {
	var b bytes.Buffer
	p := func(s string) { b.WriteString(s + "\n") }
	p("#!/usr/bin/nft -f")
	p("table inet geolock")
	p("delete table inet geolock")
	p("table inet geolock {")
	p("  set pass4 {")
	p("    type ipv4_addr")
	p("    flags interval")
	p("    auto-merge")
	p("    elements = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }")
	p("  }")
	p("  set listed4 {")
	p("    type ipv4_addr")
	p("    flags interval")
	p("    auto-merge")
	p("    elements = {")
	for _, l := range lists {
		sedIndent(&b, l)
	}
	p("    }")
	p("  }")
	p("  chain input {")
	p("    type filter hook input priority filter - 5; policy accept;")
	p("    ip saddr @pass4 accept")
	if mode == "deny" {
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } ip saddr @listed4 counter drop")
	} else {
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } ip saddr != @listed4 counter drop")
	}
	p("  }")
	p("  chain forward {")
	p("    type filter hook forward priority filter - 5; policy accept;")
	p("    ip saddr @pass4 accept")
	if mode == "deny" {
		p("    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { " + ports + " } ip saddr @listed4 counter drop")
	} else {
		p("    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { " + ports + " } ip saddr != @listed4 counter drop")
	}
	p("  }")
	p("  chain output {")
	p("    type filter hook output priority filter - 5; policy accept;")
	p("    ip daddr @pass4 accept")
	if underlay {
		p(`    socket cgroupv2 level 2 "system.slice/tailscaled.service" accept comment "tailscale underlay"`)
	}
	if mode == "allow" && strings.TrimLeft(appCg, "/") != "" {
		cg := strings.TrimLeft(appCg, "/")
		lvl := strconv.Itoa(len(strings.Split(cg, "/")))
		p(`    meta nfproto ipv6 socket cgroupv2 level ` + lvl + ` "` + cg + `" drop`)
		p(`    socket cgroupv2 level ` + lvl + ` "` + cg + `" ip daddr != @listed4 drop`)
	}
	if mode == "deny" {
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } ip daddr @listed4 counter drop")
		p("    meta l4proto { tcp, udp } th sport { " + ports + " } ip daddr @listed4 counter drop")
	} else {
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } ip daddr != @listed4 counter drop")
	}
	p("  }")
	p("}")
	return b.Bytes()
}

// FilterList mirrors `cidr_filter v4` (lib/cidr.sh): every non-comment
// line must be a strict IPv4 prefix (see internal/cidr), or the whole list
// is rejected. It returns one prefix per line, newline-terminated.
func FilterList(raw []byte) ([]byte, error) {
	ps, err := cidr.ParseList(raw, cidr.V4)
	if err != nil {
		return nil, err
	}
	return []byte(strings.Join(ps, "\n") + "\n"), nil
}

// CheckCgroup mirrors the GEOLOCK_APP_CGROUP check: path segments of
// [A-Za-z0-9@._:-], so the value cannot break out of the nft string.
func CheckCgroup(cg string) error {
	if !reCgroup.MatchString(cg) {
		return fmt.Errorf("GEOLOCK_APP_CGROUP must be a cgroup path like user.slice/app.slice")
	}
	return nil
}

// stale mirrors [[ -n $(find out -mtime +N) ]].
func stale(st os.FileInfo, days string) bool {
	var n int
	fmt.Sscanf(days, "%d", &n)
	age := int(time.Since(st.ModTime()) / (24 * time.Hour))
	return age > n
}

func fetchCC(cc, cache, urlBase, maxAge string, refresh bool) bool {
	out := filepath.Join(cache, cc+".v4")
	if st, err := os.Stat(out); !refresh && err == nil && st.Size() > 0 && !stale(st, maxAge) {
		return true
	}
	tmp := shx.MustTemp(filepath.Join(cache, "."+cc+".XXXXXX"))
	var body bytes.Buffer
	rc := shx.Cmd{Argv: []string{"curl", "-fsSL", "--retry", "2", "--max-time", "60", urlBase + "/" + cc + "/ipv4-aggregated.txt"}, Stdout: &body}.Run()
	filtered, ferr := FilterList(body.Bytes())
	if rc == 0 && ferr != nil {
		fmt.Fprintf(os.Stderr, "cidr: %v\n", ferr)
	}
	if err := os.WriteFile(tmp, filtered, 0o600); err == nil && rc == 0 && ferr == nil {
		shx.Chmod(0o644, tmp)
		shx.MvF(tmp, out)
		return true
	}
	os.Remove(tmp)
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		fmt.Fprintf(os.Stderr, "geolock: WARNING %s download failed, keeping cached list from %s\n", strings.ToUpper(cc), st.ModTime().Format("2006-01-02"))
		return true
	}
	fmt.Fprintf(os.Stderr, "geolock: ERROR %s download failed and there is no cached list\n", strings.ToUpper(cc))
	return false
}

func run() int {
	root := shx.Root()
	argv0 := shx.Argv0(filepath.Join(root, "scripts", "geolock-apply.sh"))
	envf := shx.EnvOr("GEOLOCK_SETTINGS", root+"/geolock/settings.env")
	cache := shx.EnvOr("GEOLOCK_CACHE", root+"/geolock/cache")
	nftOut := cache + "/geolock.nft"
	urlBase := shx.EnvOr("GEOLOCK_URL_BASE", "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country")
	dry := shx.EnvOr("GEOLOCK_DRY_RUN", "0")
	refresh := len(os.Args) > 1 && os.Args[1] == "--refresh"

	if !shx.IsFile(envf) {
		die("missing %s. Copy geolock/settings.env.example first.", envf)
	}
	data, err := os.ReadFile(envf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: line 1: %s: Permission denied\n", argv0, envf)
		return 1
	}
	if err := ParseSettings(envf, data, settings, os.Stderr); err != nil {
		die("%s", err)
	}
	if dry != "1" && shx.UID() != 0 {
		die("re-run as root: sudo %s", argv0)
	}
	mode := settings["GEOLOCK_MODE"]
	if settings["GEOLOCK_ENABLED"] != "1" {
		if dry != "1" {
			shx.Quiet("nft", "delete", "table", "inet", "geolock")
		}
		fmt.Println("geolock disabled (table removed if present)")
		return 0
	}
	raw := settings["GEOLOCK_ALLOW_COUNTRIES"]
	if mode == "deny" {
		raw = settings["GEOLOCK_DENY_COUNTRIES"]
	}
	codes, err := Codes(raw)
	if err != nil {
		die("%s", err)
	}
	if len(codes) == 0 {
		die("no country codes set for mode %s", mode)
	}
	ports := strings.ReplaceAll(settings["GEOLOCK_PORTS"], ",", ", ")

	shx.MkdirP(cache)
	shx.Chmod(0o755, cache)

	failed := false
	for _, cc := range codes {
		if !fetchCC(cc, cache, urlBase, settings["GEOLOCK_MAX_AGE_DAYS"], refresh) {
			failed = true
		}
	}
	if failed {
		die("not applying; fix the downloads above and re-run")
	}

	// Re-check every cached list before use: caches written by older,
	// laxer versions (or damaged on disk) must never reach nft.
	var lists [][]byte
	for _, cc := range codes {
		raw, err := os.ReadFile(filepath.Join(cache, cc+".v4"))
		var l []byte
		if err == nil {
			l, err = FilterList(raw)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "cidr: %v\n", err)
			die("cached %s list failed validation; nothing changed (try --refresh)", strings.ToUpper(cc))
		}
		lists = append(lists, l)
	}
	appCg := strings.TrimLeft(os.Getenv("GEOLOCK_APP_CGROUP"), "/")
	if mode == "allow" && appCg != "" {
		if err := CheckCgroup(appCg); err != nil {
			die("%s", err)
		}
	}
	tmpNft := shx.MustTemp(cache + "/.geolock.XXXXXX.nft")
	clear := shx.Trap(func() { os.Remove(tmpNft) })
	underlay := os.Getenv("GEOLOCK_TAILSCALE_UNDERLAY") == "1"
	if err := os.WriteFile(tmpNft, Ruleset(mode, ports, underlay, os.Getenv("GEOLOCK_APP_CGROUP"), lists), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var rc int
	if shx.UID() == 0 {
		rc = shx.Run("nft", "-c", "-f", tmpNft)
	} else {
		rc = shx.Run("unshare", "-rn", "nft", "-c", "-f", tmpNft)
	}
	if rc != 0 {
		die("generated ruleset failed nft -c; nothing changed")
	}
	shx.Chmod(0o644, tmpNft)
	shx.MvF(tmpNft, nftOut)
	clear()
	codesUp := strings.ToUpper(strings.Join(codes, " "))
	if dry == "1" {
		fmt.Printf("geolock dry run OK: %s mode=%s codes=%s\n", nftOut, mode, codesUp)
		return 0
	}
	shx.Must("nft", "-f", nftOut)
	fmt.Printf("geolock applied mode=%s codes=%s\n", mode, codesUp)
	fmt.Println("drop counters: nft list table inet geolock | grep counter")
	return 0
}

func main() { shx.Main(run) }
