// import-lists: import webpwnized/pihole-automation lists.txt into Pi-hole
// gravity.db. Go port of automation/import-lists.py (no args, same
// output). Test-only overrides: IMPORT_LISTS_FILE, IMPORT_LISTS_DB.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"

	_ "modernc.org/sqlite"

	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

// missingLists explains where the list of adlist URLs comes from.
func missingLists(p string) string {
	return "import-lists: no list file at " + p + ".\n" +
		"Clone https://github.com/webpwnized/pihole-automation into the checkout (pihole-automation/), " +
		"or set IMPORT_LISTS_FILE to a file with one adlist URL per line."
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// URLs returns unique lines starting with "http", in file order.
func URLs(text string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, line := range py.SplitLines(text) {
		u := py.Strip(line)
		if strings.HasPrefix(u, "http") && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func run(lists, dbPath string, stdout io.Writer) error {
	raw, err := os.ReadFile(lists)
	if err != nil {
		return err
	}
	items := URLs(string(raw))
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	added := int64(0)
	for _, u := range items {
		res, err := tx.Exec(`
            INSERT INTO adlist (address, enabled, comment)
            SELECT ?, 1, 'webpwnized/pihole-automation'
            WHERE NOT EXISTS (SELECT 1 FROM adlist WHERE address = ?)
            `, u, u)
		if err != nil {
			tx.Rollback()
			return err
		}
		n, _ := res.RowsAffected()
		added += n
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	var total, enabled int64
	if err := db.QueryRow("SELECT COUNT(*) FROM adlist").Scan(&total); err != nil {
		return err
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM adlist WHERE enabled=1").Scan(&enabled); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "lists in file: %d\n", len(items))
	fmt.Fprintf(stdout, "newly inserted: %d\n", added)
	fmt.Fprintf(stdout, "adlists now: %d enabled / %d total\n", enabled, total)
	fmt.Fprintln(stdout, "Run: docker exec pihole pihole -g")
	return nil
}

func main() {
	root := shx.Root()
	lists := envOr("IMPORT_LISTS_FILE", root+"/pihole-automation/lists.txt")
	if _, err := os.Stat(lists); err != nil {
		fmt.Fprintln(os.Stderr, missingLists(lists))
		os.Exit(2)
	}
	db := envOr("IMPORT_LISTS_DB", root+"/etc-pihole/gravity.db")
	if err := run(lists, db, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "import-lists: %v\n", err)
		os.Exit(1)
	}
}
