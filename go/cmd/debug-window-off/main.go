// debug-window-off: turn off the temporary Pi-hole/Unbound debug window
// (FTL debug flags off, Unbound verbosity 0, serve-expired yes). Go port of
// automation/debug-window-off.sh.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	. "pihole/go/internal/priv"
	"pihole/go/internal/py"
	"pihole/go/internal/shx"
)

var reVerb = regexp.MustCompile(`verbosity: [1-5]`)

func loadState(p string) *py.Map {
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\nFileNotFoundError: [Errno 2] No such file or directory: '%s'\n", p)
		shx.Fail(1)
	}
	v, err := py.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Traceback (most recent call last):\njson.decoder.JSONDecodeError: "+err.Error())
		shx.Fail(1)
	}
	m, ok := v.(*py.Map)
	if !ok {
		tn := "NoneType"
		switch t := v.(type) {
		case []any:
			tn = "list"
		case string:
			tn = "str"
		case bool:
			tn = "bool"
		case json.Number:
			tn = "int"
			if strings.ContainsAny(string(t), ".eE") {
				tn = "float"
			}
		case float64:
			tn = "float"
		}
		fmt.Fprintf(os.Stderr, "Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n    import json,sys; print(bool(json.load(open(sys.argv[1])).get(\"active\")))\n                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAttributeError: '%s' object has no attribute 'get'\n", tn)
		shx.Fail(1)
	}
	return m
}

func run() int {
	root := shx.Root()
	probe := Probe(root)
	state := root + "/state/debug-window.json"
	conf := root + "/unbound/custom.conf.d/hardening.conf"
	shx.MkdirP(root + "/logs")
	shx.RedirectToLog(root + "/logs/debug-window-off.log")
	fmt.Printf("[%s] debug-window-off start\n", shx.DateISO())

	if !shx.IsFile(state) {
		Echo("no state file; nothing to do")
		return 0
	}
	if !py.Truthy(loadState(state).GetOr("active", nil)) {
		Echo("window already inactive")
		return 0
	}

	R("systemctl", "--user", "stop", "pihole-watchdog.timer")
	ftl := 0
	for _, k := range []string{"debug.queries", "debug.flags", "debug.resolver", "debug.status", "misc.extraLogging"} {
		ftl = R("docker", "exec", "pihole", "pihole-FTL", "--config", k, "false")
	}
	Echo(fmt.Sprintf("ftl revert rc=%d", ftl))

	if R("grep", "-q", "serve-expired: no", conf) == 0 {
		M("sed", "-i", "s/serve-expired: no/serve-expired: yes/", conf)
	}
	if R("grep", "-qE", "verbosity: [1-5]", conf) == 0 {
		text := PyReadText(conf)
		start := strings.Index(text, "    # Temporary debug window.")
		verb := strings.Index(text, "    verbosity:")
		if start != -1 && verb != -1 && start < verb {
			end := strings.Index(text[verb:], "\n")
			tail := text[len(text)-1:] // python text[-1:] when find() is -1
			if end != -1 {
				tail = text[verb+end:]
			}
			text = text[:start] + "    verbosity: 0" + tail
		} else if loc := reVerb.FindStringIndex(text); loc != nil {
			text = text[:loc[0]] + "verbosity: 0" + text[loc[1]:]
		}
		PyWriteText(conf, text)
		shx.Chmod(0o644, conf)
		M("docker", "restart", "unbound")
		for i := 0; i < 20; i++ {
			raw, rc := shx.OutputRaw(io.Discard, "docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", "unbound")
			st := shx.OrEcho(raw, rc, "missing")
			Echo("unbound health=" + st)
			if st == "healthy" {
				break
			}
			Sleep("2")
		}
	}

	m := loadState(state)
	m.Set("active", false)
	m.Set("reverted", time.Now().Format("2006-01-02T15:04:05-07:00"))
	if err := os.WriteFile(state, []byte(py.DumpsIndent(m, 2)), 0o666); err != nil {
		return 1
	}
	Echo("state marked inactive")

	R("systemctl", "--user", "start", "pihole-watchdog.timer")
	if ProbeRC(probe, "example.com", "127.0.0.1") == 0 {
		Echo("probe ok")
	} else {
		Echo("ERROR: probe failed after revert")
		return 1
	}
	fmt.Printf("[%s] debug-window-off done\n", shx.DateISO())
	return 0
}

func main() { shx.Main(run) }
