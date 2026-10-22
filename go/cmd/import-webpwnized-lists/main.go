// import-webpwnized-lists: import pihole-automation/lists.txt into the
// running Pi-hole, then run gravity. Go port of automation/import-lists.sh
// (named apart from the phase-1 import-lists tool). Like the shell it adds
// every listed URL that is not already an adlist.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"pihole/go/internal/conf"
	. "pihole/go/internal/priv"
	"pihole/go/internal/shx"
)

var reURL = regexp.MustCompile(`^https?://`)

func run() int {
	root := shx.Root()
	lists := conf.Get("IMPORT_LISTS_FILE", root+"/pihole-automation/lists.txt")
	if _, err := os.Stat(lists); err != nil {
		Err("import-lists.sh: no list file at " + lists + ".\n" +
			"Clone https://github.com/webpwnized/pihole-automation into the checkout (pihole-automation/), " +
			"or set IMPORT_LISTS_FILE to a file with one adlist URL per line.")
		return 2
	}
	sqlPath := shx.MustTemp("")
	shx.Trap(func() { os.Remove(sqlPath) })

	f, err := os.OpenFile(sqlPath, os.O_TRUNC|os.O_WRONLY, 0)
	if err != nil {
		return 1
	}
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "BEGIN;")
	data, rerr := os.ReadFile(lists)
	if rerr != nil {
		w.Flush()
		f.Close()
		fmt.Fprintf(os.Stderr, "grep: %s: No such file or directory\n", lists)
		return 2
	}
	var urls []string
	count := 0
	seen := map[string]bool{}
	text := string(data)
	lines := strings.Split(text, "\n")
	if strings.HasSuffix(text, "\n") {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		if !reURL.MatchString(l) {
			continue
		}
		count++
		if len(strings.Fields(l)) == 0 || seen[l] {
			continue
		}
		seen[l] = true
		urls = append(urls, l)
	}
	for _, u := range urls {
		esc := strings.ReplaceAll(u, "'", "''")
		fmt.Fprintf(w, "INSERT INTO adlist (address, enabled, comment) SELECT '%s', 1, 'webpwnized/pihole-automation' WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address='%s');\n", esc, esc)
	}
	if count == 0 { // grep found nothing: pipefail + set -e end the script
		w.Flush()
		f.Close()
		return 1
	}
	fmt.Fprintln(w, "SELECT COUNT(*) AS enabled FROM adlist WHERE enabled=1;")
	fmt.Fprintln(w, "COMMIT;")
	w.Flush()
	f.Close()

	Echo(fmt.Sprintf("Importing %d list URLs...", count))
	in, err := os.Open(sqlPath)
	if err != nil {
		return 1
	}
	rc := shx.Cmd{Argv: []string{"docker", "exec", "-i", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db"}, Stdin: in}.Run()
	in.Close()
	if rc != 0 {
		return rc
	}
	Echo("Done. Updating gravity...")
	M("docker", "exec", "pihole", "pihole", "-g")
	return 0
}

var _ = io.Discard

func main() { shx.Main(run) }
