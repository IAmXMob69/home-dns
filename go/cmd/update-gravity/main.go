// update-gravity: daily Pi-hole gravity update for Docker Pi-hole. Go port
// of automation/update-gravity.sh (same log lines, SQL, docker calls,
// state/last-gravity.json, notify-send and exit codes).
package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

const (
	db        = "/etc/pihole/gravity.db"
	countLink = "SELECT COUNT(*) FROM adlist_by_group; SELECT COUNT(*) FROM domainlist_by_group;"
	restore   = `
INSERT OR IGNORE INTO "group" (id, enabled, name) VALUES (0, 1, 'Default');
INSERT OR IGNORE INTO adlist_by_group (adlist_id, group_id) SELECT id, 0 FROM adlist;
INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) SELECT id, 0 FROM domainlist;
`
	fbFix = `
DELETE FROM gravity WHERE domain IN (
  'xy.fbcdn.net','xz.fbcdn.net','||xy.fbcdn.net^','||xz.fbcdn.net^'
);
INSERT OR IGNORE INTO antigravity (domain, adlist_id)
SELECT domain, (SELECT id FROM adlist WHERE address='file:///etc/pihole/allow-facebook.txt' LIMIT 1)
FROM (
  SELECT '||facebook.com^' AS domain UNION ALL SELECT '||fb.com^' UNION ALL
  SELECT '||fbcdn.net^' UNION ALL SELECT '||xy.fbcdn.net^' UNION ALL
  SELECT '||xz.fbcdn.net^' UNION ALL SELECT '||facebook.net^' UNION ALL
  SELECT '||messenger.com^' UNION ALL SELECT '||fbsbx.com^' UNION ALL
  SELECT '||meta.com^' UNION ALL SELECT '||instagram.com^' UNION ALL
  SELECT '||cdninstagram.com^'
) d
WHERE (SELECT id FROM adlist WHERE address='file:///etc/pihole/allow-facebook.txt' LIMIT 1) IS NOT NULL;
`
)

func sqlite(q string) (string, int) {
	return shx.DockerOut(os.Stderr, "exec", "pihole", "pihole-FTL", "sqlite3", db, q)
}

// orZero mirrors "$(cmd || echo 0)".
func orZero(q string) string {
	raw, rc := shx.DockerOutRaw(os.Stderr, "exec", "pihole", "pihole-FTL", "sqlite3", db, q)
	return shx.OrEcho(raw, rc, "0")
}

func linkCounts() (string, string) {
	counts, _ := sqlite(countLink)
	return shx.Line(counts, 1, "0"), shx.Line(counts, 2, "0")
}

func restoreGroupLinks() (string, string) {
	adBg, dlBg := linkCounts()
	enAd := shx.FirstLine(orZero("SELECT COUNT(*) FROM adlist WHERE enabled=1;"), "0")
	enDl := shx.FirstLine(orZero("SELECT COUNT(*) FROM domainlist WHERE enabled=1;"), "0")
	if (arith(adBg, 41) == 0 && arith(enAd, 41) > 0) || (arith(dlBg, 42) == 0 && arith(enDl, 42) > 0) {
		fmt.Printf("[%s] WARN: group links missing (adlist_by_group=%s domainlist_by_group=%s); restoring to Default (0)\n", shx.Date(), adBg, dlBg)
		shx.MustDocker("exec", "pihole", "pihole-FTL", "sqlite3", db, restore)
		shx.MustDocker("exec", "pihole", "pihole", "reloaddns")
		adBg, dlBg = linkCounts()
		fmt.Printf("[%s] restored group links: adlist_by_group=%s domainlist_by_group=%s\n", shx.Date(), adBg, dlBg)
	} else {
		fmt.Printf("[%s] group links ok: adlist_by_group=%s domainlist_by_group=%s\n", shx.Date(), adBg, dlBg)
	}
	return adBg, dlBg
}

var reIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// arith mirrors bash [[ V -eq N ]] under set -u for the values sqlite can
// plausibly print: numbers, or a bare word (an unset variable => fatal).
// Line numbers are those of the shimmed .sh (shim adds 5 lines).
func arith(v string, line int) int64 {
	t := strings.TrimSpace(v)
	if reIdent.MatchString(t) {
		if ev, ok := os.LookupEnv(t); ok {
			return arith(ev, line)
		}
		fmt.Fprintf(os.Stderr, "%s: line %d: %s: unbound variable\n", shx.Argv0(shx.Root()+"/automation/update-gravity.sh"), line, t)
		shx.Fail(1)
	}
	return shx.BashInt(t)
}

func pyInt(s string) (int64, bool) {
	n, err := strconv.ParseInt(py.Strip(s), 10, 64)
	return n, err == nil
}

func run() int {
	root := shx.Root()
	stateDir := root + "/state"
	shx.MkdirP(root+"/logs", stateDir)
	shx.RedirectToLog(root + "/logs/update-gravity.log")

	avail := shx.DfAvailKB(root + "/etc-pihole")
	if shx.BashInt(avail) < 8388608 {
		fmt.Printf("[%s] ERROR: only %s KB free; need 8 GB before gravity\n", shx.Date(), avail)
		return 1
	}
	fmt.Printf("[%s] Pi-hole gravity update start (%s KB free)\n", shx.Date(), avail)
	if shx.Docker(shx.Cmd{}, "exec", "pihole", "pihole", "-g") != 0 {
		fmt.Printf("[%s] ERROR: gravity update failed\n", shx.Date())
		shx.Notify("Pi-hole gravity failed", "pihole -g returned non-zero")
		return 1
	}
	count := shx.FirstLine(orZero("SELECT COALESCE(value,0) FROM info WHERE property='gravity_count';"), "0")
	fmt.Printf("[%s] SUCCESS: gravity updated (%s unique list domains)\n", shx.Date(), count)
	adBg, dlBg := restoreGroupLinks()

	fmt.Printf("[%s] stripping Facebook CDN gravity + ensuring antigravity allow\n", shx.Date())
	shx.MustDocker("exec", "pihole", "pihole-FTL", "sqlite3", db, fbFix)
	shx.Docker(shx.Cmd{}, "exec", "pihole", "pihole", "reloaddns")

	vals := [3]int64{}
	for i, a := range [3]struct{ v, src string }{
		{count, "count = int(sys.argv[1])"},
		{adBg, "ad_bg = int(sys.argv[2])"},
		{dlBg, "dl_bg = int(sys.argv[3])"},
	} {
		n, ok := pyInt(a.v)
		if !ok {
			fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\n  File \"<string>\", line %d, in <module>\n    %s\nValueError: invalid literal for int() with base 10: %s\n", 5+i, a.src, py.Repr(a.v))
			return 1
		}
		vals[i] = n
	}
	c, a, d := vals[0], vals[1], vals[2]
	out := py.O("ts", shx.DateISO(), "gravity_count", c, "adlist_by_group", a, "domainlist_by_group", d)
	if err := os.WriteFile(stateDir+"/last-gravity.json", []byte(py.Dumps(out, true)), 0o666); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if shx.BashInt(count) < 100000 {
		fmt.Printf("[%s] ERROR: gravity_count %s < 100000\n", shx.Date(), count)
		shx.Notify("Pi-hole gravity low", "gravity_count="+count+" (need >= 100000)")
		return 1
	}
	return 0
}

func main() { shx.Main(run) }
