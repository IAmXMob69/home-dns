// backup: config-only Pi-hole backup (teleporter zip, else a tar.gz without
// gravity/FTL databases), keeping the newest 3. Go port of backup.sh.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"pihole/go/internal/shx"
)

const keep = 3

func run() int {
	root := shx.Root()
	dest := root + "/backups"
	shx.MkdirP(dest)
	stamp := time.Now().Format("20060102-150405")
	out := dest + "/pihole-" + stamp + ".zip"

	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", out, err)
		return 1
	}
	rc := shx.Docker(shx.Cmd{Stdout: f, Stderr: io.Discard}, "exec", "pihole", "pihole-FTL", "--teleporter")
	f.Close()
	if rc == 0 && shx.NonEmpty(out) {
		fmt.Println("Wrote " + out)
	} else {
		os.Remove(out)
		shx.Must("tar", "-C", root, "-czf", dest+"/pihole-"+stamp+".tar.gz",
			"--exclude=etc-pihole/gravity.db",
			"--exclude=etc-pihole/gravity_old.db",
			"--exclude=etc-pihole/listsCache",
			"--exclude=etc-pihole/pihole-FTL.db",
			"--exclude=etc-pihole/pihole-FTL.db-wal",
			"--exclude=etc-pihole/pihole-FTL.db-shm",
			"--exclude=etc-pihole/gravity_backups",
			"docker-compose.yml", ".env", "etc-pihole")
		fmt.Println("Wrote " + dest + "/pihole-" + stamp + ".tar.gz")
	}
	if old := shx.LsT(dest + "/pihole-*"); len(old) > keep {
		failed := false
		for _, p := range old[keep:] {
			if st, err := os.Lstat(p); err == nil && st.IsDir() {
				fmt.Fprintf(os.Stderr, "rm: cannot remove '%s': Is a directory\n", p)
				failed = true
				continue
			}
			os.Remove(p)
		}
		if failed {
			return 1
		}
	}
	return 0
}

func main() { shx.Main(run) }
