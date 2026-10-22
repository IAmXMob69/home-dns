// install-privacy-shield: install local Pi-hole deny rules for telemetry,
// analytics, crash-reporting, attribution and session-replay endpoints.
// Go port of automation/install-privacy-shield.sh (same SQL, same checks).
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

// readTab mirrors IFS=$'\t' read -r type rule comment extra: tab is IFS
// whitespace, so runs of tabs collapse and edges are trimmed; the last
// variable takes the rest of the line.
func readTab(line string) (t, rule, comment, extra string) {
	rest := strings.Trim(line, "\t")
	next := func() string {
		i := strings.IndexByte(rest, '\t')
		if i < 0 {
			v := rest
			rest = ""
			return v
		}
		v := rest[:i]
		rest = strings.TrimLeft(rest[i:], "\t")
		return v
	}
	t, rule, comment = next(), next(), next()
	extra = rest
	return
}

func esc(s string) string { return strings.ReplaceAll(s, "'", "''") }

func run() int {
	root := shx.Root()
	rules := root + "/privacy-shield/privacy-shield.tsv"
	if len(os.Args) > 1 && os.Args[1] != "" {
		rules = os.Args[1]
	}
	sqlPath := shx.MustTemp("")
	shx.Trap(func() { os.Remove(sqlPath) })

	if !shx.IsFile(rules) {
		Err("privacy shield rules not found: " + rules)
		return 1
	}

	f, err := os.OpenFile(sqlPath, os.O_TRUNC|os.O_WRONLY, 0)
	if err != nil {
		return 1
	}
	w := bufio.NewWriter(f)
	defer func() { w.Flush(); f.Close() }()
	fmt.Fprintln(w, "BEGIN;")
	fmt.Fprintln(w, `INSERT OR IGNORE INTO "group" (id, enabled, name) VALUES (0, 1, 'Network');`)

	data, err := os.ReadFile(rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: line 1: %s: Permission denied\n", shx.Argv0(root+"/automation/install-privacy-shield.sh"), rules)
		return 1
	}
	installed := 0
	text := strings.ReplaceAll(string(data), "\x00", "")
	lines := strings.Split(text, "\n")
	lines = lines[:len(lines)-1] // read fails on a final line without "\n"
	for _, line := range lines {
		typ, rule, comment, extra := readTab(line)
		if typ == "" {
			continue
		}
		if r, _ := utf8.DecodeRuneInString(typ); r == '#' {
			continue
		}
		if extra != "" {
			Err("invalid extra tab-separated field in rule: " + rule)
			return 1
		}
		if typ != "1" && typ != "3" {
			Err(fmt.Sprintf("invalid rule type '%s' for %s", typ, rule))
			return 1
		}
		if rule == "" || comment == "" {
			Err("invalid empty rule/comment in " + rules)
			return 1
		}
		rs, cs := esc(rule), esc("privacy-shield: "+comment)
		fmt.Fprintf(w, `INSERT INTO domainlist (type, domain, enabled, comment)
VALUES (%[1]s, '%[2]s', 1, '%[3]s')
ON CONFLICT(domain, type) DO UPDATE SET
  enabled = 1,
  comment = excluded.comment,
  date_modified = cast(strftime('%%s', 'now') as int);
INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id)
SELECT id, 0 FROM domainlist WHERE type = %[1]s AND domain = '%[2]s';
`, typ, rs, cs)
		installed++
	}
	fmt.Fprintln(w, "COMMIT;")
	fmt.Fprintln(w, "SELECT COUNT(*) AS privacy_shield_enabled FROM domainlist WHERE enabled=1 AND comment LIKE 'privacy-shield:%';")
	w.Flush()
	f.Close()

	Echo("Installing Pi-hole privacy shield from " + rules)
	in, err := os.Open(sqlPath)
	if err != nil {
		return 1
	}
	rc := shx.Docker(shx.Cmd{Stdin: in}, "exec", "-i", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db")
	in.Close()
	if rc != 0 {
		return rc
	}
	shx.MustDocker("exec", "pihole", "pihole", "reloaddns")
	Echo(fmt.Sprintf("Privacy shield installed (%d rules processed).", installed))
	return 0
}

func main() { shx.Main(run) }
