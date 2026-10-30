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
	reKV     = regexp.MustCompile(`^[[:space:]]*([A-Z_0-9]+)=["']?([A-Za-z0-9,._-]*)["']?[[:space:]]*$`)
	reBool   = regexp.MustCompile(`^[01]$`)
	reMode   = regexp.MustCompile(`^(allow|deny)$`)
	rePorts  = regexp.MustCompile(`^[0-9]+(,[0-9]+)*$`)
	reNum    = regexp.MustCompile(`^[0-9]+$`)
	reCC     = regexp.MustCompile(`^[a-z]{2}$`)
	reCgroup = regexp.MustCompile(`^[A-Za-z0-9@._:-]+(/[A-Za-z0-9@._:-]+)*$`)
	settings = map[string]string{
		"GEOLOCK_ENABLED": "0", "GEOLOCK_MODE": "allow", "GEOLOCK_ALLOW_COUNTRIES": "US,DE",
		"GEOLOCK_DENY_COUNTRIES": "", "GEOLOCK_PORTS": "53,853", "GEOLOCK_MAX_AGE_DAYS": "7",
		"GEOLOCK_IPV6": "0", "GEOLOCK_INBOUND": "1", "GEOLOCK_OUTBOUND": "1",
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
		case "GEOLOCK_ENABLED", "GEOLOCK_IPV6", "GEOLOCK_INBOUND", "GEOLOCK_OUTBOUND":
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

// Opts selects what Ruleset renders.
type Opts struct {
	Mode, Ports, AppCg string
	Underlay, IPv6     bool
	Inbound, Outbound  bool
}

// match mirrors the shell helper: deny mode matches the listed set, allow
// mode everything outside it.
func match(mode, sel, set string) string {
	if mode == "deny" {
		return sel + " @" + set
	}
	return sel + " != @" + set
}

// Ruleset renders geolock.nft exactly like the shell heredoc of echos.
// With IPv6=false, Inbound=Outbound=true the output is unchanged from the
// IPv4-only renderer.
func Ruleset(o Opts, v4, v6 [][]byte) []byte {
	var b bytes.Buffer
	p := func(s string) { b.WriteString(s + "\n") }
	set := func(name, typ string, lists [][]byte) {
		p("  set " + name + " {")
		p("    type " + typ)
		p("    flags interval")
		p("    auto-merge")
		p("    elements = {")
		for _, l := range lists {
			sedIndent(&b, l)
		}
		p("    }")
		p("  }")
	}
	ports, mode := o.Ports, o.Mode
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
	set("listed4", "ipv4_addr", v4)
	if o.IPv6 {
		p("  set pass6 {")
		p("    type ipv6_addr")
		p("    flags interval")
		p("    auto-merge")
		p("    elements = { ::1/128, fe80::/10, fc00::/7 }")
		p("  }")
		set("listed6", "ipv6_addr", v6)
	}
	if o.Inbound {
		p("  chain input {")
		p("    type filter hook input priority filter - 5; policy accept;")
		p("    ip saddr @pass4 accept")
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } " + match(mode, "ip saddr", "listed4") + " counter drop")
		if o.IPv6 {
			p("    ip6 saddr @pass6 accept")
			p("    meta l4proto { tcp, udp } th dport { " + ports + " } " + match(mode, "ip6 saddr", "listed6") + " counter drop")
		}
		p("  }")
		p("  chain forward {")
		p("    type filter hook forward priority filter - 5; policy accept;")
		p("    ip saddr @pass4 accept")
		p("    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { " + ports + " } " + match(mode, "ip saddr", "listed4") + " counter drop")
		if o.IPv6 {
			p("    ip6 saddr @pass6 accept")
			p("    ct status dnat meta l4proto { tcp, udp } ct original proto-dst { " + ports + " } " + match(mode, "ip6 saddr", "listed6") + " counter drop")
		}
		p("  }")
	}
	if o.Outbound {
		p("  chain output {")
		p("    type filter hook output priority filter - 5; policy accept;")
		p("    ip daddr @pass4 accept")
		if o.IPv6 {
			p("    ip6 daddr @pass6 accept")
		}
		if o.Underlay {
			p(`    socket cgroupv2 level 2 "system.slice/tailscaled.service" accept comment "tailscale underlay"`)
		}
		if cg := strings.TrimLeft(o.AppCg, "/"); mode == "allow" && cg != "" {
			lvl := strconv.Itoa(len(strings.Split(cg, "/")))
			if o.IPv6 {
				p(`    socket cgroupv2 level ` + lvl + ` "` + cg + `" ip6 daddr != @listed6 drop`)
			} else {
				p(`    meta nfproto ipv6 socket cgroupv2 level ` + lvl + ` "` + cg + `" drop`)
			}
			p(`    socket cgroupv2 level ` + lvl + ` "` + cg + `" ip daddr != @listed4 drop`)
		}
		p("    meta l4proto { tcp, udp } th dport { " + ports + " } " + match(mode, "ip daddr", "listed4") + " counter drop")
		if mode == "deny" {
			p("    meta l4proto { tcp, udp } th sport { " + ports + " } ip daddr @listed4 counter drop")
		}
		if o.IPv6 {
			p("    meta l4proto { tcp, udp } th dport { " + ports + " } " + match(mode, "ip6 daddr", "listed6") + " counter drop")
			if mode == "deny" {
				p("    meta l4proto { tcp, udp } th sport { " + ports + " } ip6 daddr @listed6 counter drop")
			}
		}
		p("  }")
	}
	p("}")
	return b.Bytes()
}

// Expect is what verify checks after a load: drop rules per chain and the
// first address of each listed set.
type Expect struct {
	Drops map[string]int    // chain -> number of rules ending in " drop"
	First map[string]string // set -> first element address (prefix stripped)
}

// ParseExpect mirrors the two awk programs in verify_loaded.
func ParseExpect(nft []byte) Expect {
	e := Expect{Drops: map[string]int{}, First: map[string]string{}}
	chain, set := "", ""
	for _, l := range strings.Split(string(nft), "\n") {
		switch {
		case strings.HasPrefix(l, "  chain ") && strings.HasSuffix(l, " {"):
			chain = strings.TrimSuffix(strings.TrimPrefix(l, "  chain "), " {")
			e.Drops[chain] += 0
		case strings.HasPrefix(l, "  set ") && strings.HasSuffix(l, " {"):
			set = strings.TrimSuffix(strings.TrimPrefix(l, "  set "), " {")
		case l == "  }":
			chain, set = "", ""
		case chain != "" && strings.HasSuffix(l, " drop"):
			e.Drops[chain]++
		case set != "" && strings.HasPrefix(l, "      "):
			if _, ok := e.First[set]; !ok {
				a := strings.TrimLeft(l, " ")
				if i := strings.IndexByte(a, '/'); i >= 0 {
					a = a[:i]
				}
				e.First[set] = a
			}
		}
	}
	return e
}

// FilterList mirrors `cidr_filter v4` (lib/cidr.sh): every non-comment
// line must be a strict IPv4 prefix (see internal/cidr), or the whole list
// is rejected. It returns one prefix per line, newline-terminated.
func FilterList(raw []byte) ([]byte, error) { return filterFam(raw, "v4") }

// filterFam mirrors `cidr_filter v4|v6`.
func filterFam(raw []byte, fam string) ([]byte, error) {
	f := cidr.V4
	if fam == "v6" {
		f = cidr.V6
	}
	ps, err := cidr.ParseList(raw, f)
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

// what names a list in messages: "US" or "US IPv6".
func what(cc, fam string) string {
	if fam == "v6" {
		return strings.ToUpper(cc) + " IPv6"
	}
	return strings.ToUpper(cc)
}

func fetchCC(cc, fam, cache, urlBase, maxAge string, refresh bool) bool {
	out := filepath.Join(cache, cc+"."+fam)
	if st, err := os.Stat(out); !refresh && err == nil && st.Size() > 0 && !stale(st, maxAge) {
		return true
	}
	tmp := shx.MustTemp(filepath.Join(cache, "."+cc+".XXXXXX"))
	url := urlBase + "/" + cc + "/ip" + fam + "-aggregated.txt"
	var body bytes.Buffer
	var rc int
	ok := false
	var filtered []byte
	var ferr error
	if fam == "v6" {
		// No upstream file means no IPv6 allocations: record an empty
		// cache file, but never let a 404 replace a good cached list.
		var code bytes.Buffer
		rc = shx.Cmd{Argv: []string{"curl", "-sSL", "--retry", "2", "--max-time", "60", "-o", tmp, "-w", "%{http_code}", url}, Stdout: &code}.Run()
		if (rc == 37 || (rc == 0 && code.String() == "404")) && !shx.NonEmpty(out) {
			if err := os.WriteFile(tmp, nil, 0o600); err == nil {
				shx.Chmod(0o644, tmp)
				shx.MvF(tmp, out)
				fmt.Fprintf(os.Stderr, "geolock: note: %s has no list upstream; nothing listed for it\n", what(cc, fam))
				return true
			}
		}
		if rc == 0 && (code.String() == "200" || code.String() == "000") {
			raw, err := os.ReadFile(tmp)
			if err == nil {
				filtered, ferr = filterFam(raw, fam)
				if ferr != nil {
					fmt.Fprintf(os.Stderr, "cidr: %v\n", ferr)
				}
				ok = ferr == nil
			}
		}
	} else {
		rc = shx.Cmd{Argv: []string{"curl", "-fsSL", "--retry", "2", "--max-time", "60", url}, Stdout: &body}.Run()
		filtered, ferr = filterFam(body.Bytes(), fam)
		if rc == 0 && ferr != nil {
			fmt.Fprintf(os.Stderr, "cidr: %v\n", ferr)
		}
		ok = rc == 0 && ferr == nil
	}
	if ok {
		if err := os.WriteFile(tmp, filtered, 0o600); err == nil {
			shx.Chmod(0o644, tmp)
			shx.MvF(tmp, out)
			return true
		}
	}
	os.Remove(tmp)
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		fmt.Fprintf(os.Stderr, "geolock: WARNING %s download failed, keeping cached list from %s\n", what(cc, fam), st.ModTime().Format("2006-01-02"))
		return true
	}
	fmt.Fprintf(os.Stderr, "geolock: ERROR %s download failed and there is no cached list\n", what(cc, fam))
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
	nftBin := shx.EnvOr("GEOLOCK_NFT", "nft")

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
			shx.Quiet(nftBin, "delete", "table", "inet", "geolock")
		}
		fmt.Println("geolock disabled (table removed if present)")
		return 0
	}
	if settings["GEOLOCK_INBOUND"] != "1" && settings["GEOLOCK_OUTBOUND"] != "1" {
		die("GEOLOCK_INBOUND and GEOLOCK_OUTBOUND are both 0; use GEOLOCK_ENABLED=0 instead")
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
	ipv6 := settings["GEOLOCK_IPV6"] == "1"
	fams := []string{"v4"}
	if ipv6 {
		fams = append(fams, "v6")
	}

	shx.MkdirP(cache)
	shx.Chmod(0o755, cache)

	failed := false
	for _, fam := range fams {
		for _, cc := range codes {
			if !fetchCC(cc, fam, cache, urlBase, settings["GEOLOCK_MAX_AGE_DAYS"], refresh) {
				failed = true
			}
		}
	}
	if failed {
		die("not applying; fix the downloads above and re-run")
	}

	// Re-check every cached list before use: caches written by older,
	// laxer versions (or damaged on disk) must never reach nft.
	lists := map[string][][]byte{}
	any6 := false
	for _, fam := range fams {
		for _, cc := range codes {
			path := filepath.Join(cache, cc+"."+fam)
			if st, err := os.Stat(path); fam == "v6" && err == nil && st.Mode().IsRegular() && st.Size() == 0 {
				lists[fam] = append(lists[fam], nil) // no IPv6 allocations upstream
				continue
			}
			raw, err := os.ReadFile(path)
			var l []byte
			if err == nil {
				l, err = filterFam(raw, fam)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "cidr: %v\n", err)
				die("cached %s list failed validation; nothing changed (try --refresh)", what(cc, fam))
			}
			if fam == "v6" {
				any6 = true
			}
			lists[fam] = append(lists[fam], l)
		}
	}
	if ipv6 && !any6 {
		die("no IPv6 prefixes for any selected country; set GEOLOCK_IPV6=0")
	}
	appCg := strings.TrimLeft(os.Getenv("GEOLOCK_APP_CGROUP"), "/")
	if mode == "allow" && appCg != "" {
		if err := CheckCgroup(appCg); err != nil {
			die("%s", err)
		}
	}
	tmpNft := shx.MustTemp(cache + "/.geolock.XXXXXX.nft")
	clear := shx.Trap(func() { os.Remove(tmpNft) })
	o := Opts{
		Mode: mode, Ports: ports, AppCg: appCg, IPv6: ipv6,
		Underlay: os.Getenv("GEOLOCK_TAILSCALE_UNDERLAY") == "1",
		Inbound:  settings["GEOLOCK_INBOUND"] == "1",
		Outbound: settings["GEOLOCK_OUTBOUND"] == "1",
	}
	rendered := Ruleset(o, lists["v4"], lists["v6"])
	if err := os.WriteFile(tmpNft, rendered, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var rc int
	if shx.UID() == 0 {
		rc = shx.Run(nftBin, "-c", "-f", tmpNft)
	} else {
		rc = shx.Run("unshare", "-rn", nftBin, "-c", "-f", tmpNft)
	}
	if rc != 0 {
		die("generated ruleset failed nft -c; nothing changed")
	}
	shx.Chmod(0o644, tmpNft)
	codesUp := strings.ToUpper(strings.Join(codes, " "))
	if dry == "1" {
		shx.MvF(tmpNft, nftOut)
		clear()
		fmt.Printf("geolock dry run OK: %s mode=%s codes=%s\n", nftOut, mode, codesUp)
		return 0
	}
	return loadVerifyRollback(nftBin, cache, nftOut, tmpNft, rendered, clear, mode, codesUp)
}

// loadVerifyRollback mirrors the "load, verify, roll back" block of
// scripts/geolock-apply.sh.
func loadVerifyRollback(nftBin, cache, nftOut, tmpNft string, rendered []byte, clear func(), mode, codesUp string) int {
	prev := cache + "/geolock.prev.nft"
	hadTable := false
	snap := shx.MustTemp(cache + "/.geolock.prev.XXXXXX")
	clear()
	clear = shx.Trap(func() { os.Remove(tmpNft); os.Remove(snap) })
	body, rc := shx.OutputRaw(io.Discard, nftBin, "list", "table", "inet", "geolock")
	if rc == 0 {
		hadTable = true
		if err := os.WriteFile(snap, []byte("#!/usr/bin/nft -f\ntable inet geolock\ndelete table inet geolock\n"+body), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if shx.Run(nftBin, "-c", "-f", snap) != 0 {
			die("cannot snapshot the live geolock table for rollback; nothing changed")
		}
		shx.Chmod(0o600, snap)
		shx.MvF(snap, prev)
	} else {
		os.Remove(snap)
	}

	hadOut := false
	if shx.NonEmpty(nftOut) {
		if shx.Run("cp", "-p", nftOut, nftOut+".bak") == 0 {
			hadOut = true
		}
	}
	shx.MvF(tmpNft, nftOut)
	clear()
	if shx.Run(nftBin, "-f", nftOut) == 0 && verifyLoaded(nftBin, ParseExpect(rendered)) {
		os.Remove(nftOut + ".bak")
		fmt.Printf("geolock applied mode=%s codes=%s\n", mode, codesUp)
		fmt.Println("drop counters: nft list table inet geolock | grep counter")
		return 0
	}
	shx.MvF(nftOut, cache+"/geolock.failed.nft")
	if hadOut {
		shx.MvF(nftOut+".bak", nftOut)
	}
	if hadTable {
		if shx.Run(nftBin, "-f", prev) == 0 {
			die("new ruleset failed to load or verify; rolled back to the previous table (see %s/geolock.failed.nft)", cache)
		}
		die("new ruleset failed AND rollback from %s failed; check: nft list table inet geolock", prev)
	}
	die("new ruleset failed to load or verify and there was no previous table (see %s/geolock.failed.nft)", cache)
	return 1
}

// verifyLoaded mirrors verify_loaded in scripts/geolock-apply.sh.
func verifyLoaded(nftBin string, e Expect) bool {
	for _, c := range []string{"input", "forward", "output"} {
		want, ok := e.Drops[c]
		if !ok {
			continue
		}
		out, rc := shx.OutputRaw(io.Discard, nftBin, "list", "chain", "inet", "geolock", c)
		if rc != 0 {
			return false
		}
		got := 0
		for _, l := range strings.Split(out, "\n") {
			if strings.HasSuffix(l, " drop") {
				got++
			}
		}
		if got != want {
			fmt.Fprintf(os.Stderr, "geolock: verify: chain %s has %d drop rules, expected %d\n", c, got, want)
			return false
		}
	}
	for _, set := range []string{"listed4", "listed6"} {
		first, ok := e.First[set]
		if !ok {
			continue
		}
		if shx.Quiet(nftBin, "get", "element", "inet", "geolock", set, "{ "+first+" }") != 0 {
			fmt.Fprintf(os.Stderr, "geolock: verify: %s missing from set %s\n", first, set)
			return false
		}
	}
	return true
}

func main() { shx.Main(run) }
