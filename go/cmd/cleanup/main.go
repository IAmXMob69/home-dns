// cleanup: drop Pi-hole junk that rebuilds itself (old probe logs, debug
// logs, orphan list caches, extra backups, oversized logs, dangling images).
// Go port of cleanup.sh. Never deletes gravity.db or listsCache contents
// that belong to a current adlist. The du/df report lines still come from
// du(1)/df(1) so their numbers and wording stay identical.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"

	"pihole/go/internal/shx"
)

var reList = regexp.MustCompile(`^list\.(\d+)\.`)

// cleanTmp mirrors find DIR -maxdepth 1 -user ME \( -name 'pihole-*.log' -o -name 'pihole-*.html' \) -delete 2>/dev/null.
func cleanTmp(dir string, uid int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		m1, _ := filepath.Match("pihole-*.log", n)
		m2, _ := filepath.Match("pihole-*.html", n)
		if !m1 && !m2 {
			continue
		}
		p := filepath.Join(dir, n)
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if s, ok := st.Sys().(*syscall.Stat_t); ok && int(s.Uid) == uid {
			os.Remove(p)
		}
	}
}

// OrphanCache mirrors the embedded python: delete listsCache/list.<id>.*
// files whose id is no longer an adlist. Returns the summary line ("" if
// nothing removed) and an error for the cases python would crash on.
func OrphanCache(etc string) (string, error) {
	cache := filepath.Join(etc, "listsCache")
	db := filepath.Join(etc, "gravity.db")
	if st, err := os.Stat(cache); err != nil || !st.IsDir() || !shx.IsFile(db) {
		return "", nil
	}
	con, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer con.Close()
	rows, err := con.Query("SELECT id FROM adlist")
	if err != nil {
		m := strings.TrimSuffix(strings.TrimPrefix(err.Error(), "SQL logic error: "), " (1)")
		return "", fmt.Errorf("  File \"<stdin>\", line 8, in <module>\nsqlite3.OperationalError: %s", m)
	}
	ids := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids[id] = true
		}
	}
	rows.Close()
	// Raw getdents order, like pathlib.iterdir (os.ReadDir would sort).
	d, err := os.Open(cache)
	if err != nil {
		return "", err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return "", err
	}
	removed, bytes := 0, int64(0)
	for _, name := range names {
		m := reList.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		id, _ := strconv.ParseInt(m[1], 10, 64)
		if ids[id] {
			continue
		}
		p := filepath.Join(cache, name)
		st, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if st.IsDir() {
			return "", fmt.Errorf("  File \"<stdin>\", line 16, in <module>\nIsADirectoryError: [Errno 21] Is a directory: '%s'", p)
		}
		if err := os.Remove(p); err != nil {
			return "", err
		}
		bytes += st.Size()
		removed++
	}
	if removed > 0 {
		return fmt.Sprintf("removed %d orphan cache files (%d bytes)", removed, bytes), nil
	}
	return "", nil
}

func capLogs(dir string) {
	for _, f := range shx.Glob(dir + "/*.log") {
		st, err := os.Stat(f)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if st.Size() > 1048576 {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if len(data) > 262144 {
				data = data[len(data)-262144:]
			}
			if os.WriteFile(f+".tmp", data, 0o666) == nil {
				shx.MvF(f+".tmp", f)
			}
		}
	}
}

func duH(p string) string {
	out, _ := shx.Output(os.Stderr, "du", "-sh", p)
	if f := strings.Fields(out); len(f) > 0 {
		return f[0]
	}
	return ""
}

func run() int {
	root := shx.Root()
	shx.MkdirP(root + "/logs")
	shx.RedirectToLog(root + "/logs/cleanup.log")
	fmt.Printf("[%s] cleanup start\n", shx.Date())

	cleanTmp("/tmp", shx.UID())

	dockerOK := shx.Docker(shx.Cmd{Stdout: io.Discard, Stderr: io.Discard}, "info") == 0
	if !dockerOK {
		fmt.Printf("[%s] WARN: docker unavailable via docker_cmd; skipping container cleanup\n", shx.Date())
	}
	if dockerOK {
		shx.Docker(shx.Cmd{Stderr: io.Discard}, "exec", "pihole", "rm", "-f", "/var/log/pihole/pihole_debug.log", "/var/log/pihole/pihole_updateGravity.log")
		if shx.Docker(shx.Cmd{Stderr: io.Discard}, "exec", "pihole", "test", "-x", "/usr/sbin/logrotate") == 0 {
			shx.Docker(shx.Cmd{}, "exec", "pihole", "logrotate", "/etc/logrotate.d/pihole")
		}
		shx.DockerQuiet("exec", "pihole", "pihole-FTL", "sqlite3", "/etc/pihole/pihole-FTL.db", "PRAGMA wal_checkpoint(TRUNCATE);")
	}
	if shx.Quiet("sh", "-c", "command -v sqlite3") == 0 && shx.IsFile(root+"/etc-pihole/pihole-FTL.db") {
		shx.Quiet("sqlite3", root+"/etc-pihole/pihole-FTL.db", "PRAGMA wal_checkpoint(TRUNCATE);")
	}

	msg, err := OrphanCache(root + "/etc-pihole")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\n%v\n", err)
		return 1
	}
	if msg != "" {
		fmt.Println(msg)
	}

	if st, err := os.Stat(root + "/backups"); err == nil && st.IsDir() {
		if old := shx.LsT(root + "/backups/pihole-*"); len(old) > 3 {
			bad := false
			for _, p := range old[3:] {
				if st, err := os.Lstat(p); err == nil && st.IsDir() {
					fmt.Fprintf(os.Stderr, "rm: cannot remove '%s': Is a directory\n", p)
					bad = true
					continue
				}
				os.Remove(p)
			}
			if bad {
				return 1
			}
			fmt.Println("pruned extra backups")
		}
	}

	capLogs(root + "/logs")

	if dockerOK {
		shx.Docker(shx.Cmd{Stdout: io.Discard}, "image", "prune", "-f")
	}

	fmt.Printf("[%s] pihole dir %s gravity.db=%s listsCache=%s\n", shx.Date(), duH(root), duH(root+"/etc-pihole/gravity.db"), duH(root+"/etc-pihole/listsCache"))
	if out, _ := shx.Output(os.Stderr, "df", "-hP", root); out != "" {
		ls := strings.Split(out, "\n")
		if len(ls) > 1 {
			f := strings.Fields(ls[1])
			if len(f) >= 6 {
				fmt.Printf("[df] %s free on %s (%s used)\n", f[3], f[5], f[4])
			}
		}
	}
	fmt.Printf("[%s] cleanup done\n", shx.Date())
	return 0
}

func main() { shx.Main(run) }
