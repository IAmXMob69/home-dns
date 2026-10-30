// indic-idn-guard: deny DNS names written in Indian scripts.
//
// Pi-hole regex sees only the punycode form (xn--...) of a name, so it
// cannot tell which script a label is in. This tool reads the names
// Pi-hole answered recently (read-only, from the long-term query
// database inside the pihole container), decodes every xn-- label with
// golang.org/x/net/idna, and adds an exact deny entry for each name with
// a label in an Indic script.
//
// Scripts: Devanagari (incl. Extended and Extended-A), Bengali/Assamese,
// Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Ol Chiki,
// Meetei Mayek (incl. Extensions) and Vedic Extensions.
//
// Not covered, on purpose: Arabic script (Urdu shares it with many
// countries), Latin (Hindi typed in Latin letters looks like any other
// name), and any page content (DNS only sees names).
//
// Safety:
//   - Only adds exact deny entries tagged with --comment. Never deletes,
//     never touches allow entries, regex entries, groups or gravity.db.
//   - Names are converted to ASCII and strictly validated before they
//     reach the Pi-hole CLI, which is run without a shell.
//   - --max caps how many names one run may add. --dry-run adds nothing.
//   - Names under India's IDN TLDs are skipped; the TLD regex covers them.
//
// Undo: pihole deny remove <name>, or delete entries commented
// "india-lang indic-idn-guard" in the Pi-hole admin page.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// IndiaIDNTLDs are India's IDN ccTLDs as listed in the IANA root zone
// database (sponsor: National Internet Exchange of India).
var IndiaIDNTLDs = []string{
	"xn--h2brj9c",       // भारत Devanagari
	"xn--h2breg3eve",    // भारतम् Devanagari
	"xn--h2brj9c8c",     // भारोत Devanagari
	"xn--45brj9c",       // ভারত Bengali
	"xn--45br5cyl",      // ভাৰত Bengali (Assamese)
	"xn--s9brj9c",       // ਭਾਰਤ Gurmukhi
	"xn--gecrj9c",       // ભારત Gujarati
	"xn--3hcrj9c",       // ଭାରତ Oriya
	"xn--xkc2dl3a5ee0h", // இந்தியா Tamil
	"xn--fpcrj9c3d",     // భారత్ Telugu
	"xn--2scrj9c",       // ಭಾರತ Kannada
	"xn--rvc1e0am3e",    // ഭാരതം Malayalam
	"xn--mgbbh1a71e",    // بھارت Arabic (Urdu)
	"xn--mgbbh1a",       // بارت Arabic (Kashmiri)
	"xn--mgbgu82a",      // ڀارت Arabic (Sindhi)
}

var indicTables = []*unicode.RangeTable{
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada,
	unicode.Malayalam, unicode.Ol_Chiki, unicode.Meetei_Mayek,
}

// IsIndicRune reports whether r belongs to one of the covered scripts.
func IsIndicRune(r rune) bool {
	switch {
	case r >= 0x1CD0 && r <= 0x1CFF: // Vedic Extensions (mostly script Inherited)
		return true
	case r >= 0xA8E0 && r <= 0xA8FF: // Devanagari Extended
		return true
	case r >= 0x11B00 && r <= 0x11B5F: // Devanagari Extended-A
		return true
	case r >= 0xAAE0 && r <= 0xAAFF: // Meetei Mayek Extensions
		return true
	}
	return unicode.IsOneOf(indicTables, r)
}

var asciiName = regexp.MustCompile(`^([a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Classify decodes name and reports whether any label is in an Indic
// script. ascii is the validated punycode form to hand to Pi-hole.
func Classify(name string) (indic bool, ascii string, err error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return false, "", fmt.Errorf("empty name")
	}
	for _, label := range strings.Split(name, ".") {
		var u string
		switch {
		case strings.HasPrefix(label, "xn--"):
			u, err = idna.Punycode.ToUnicode(label)
			if err != nil || u == label {
				return false, "", fmt.Errorf("bad punycode label %q", label)
			}
		default:
			u = label
		}
		for _, r := range u {
			if IsIndicRune(r) {
				indic = true
			}
		}
	}
	ascii, err = idna.Punycode.ToASCII(name)
	if err != nil {
		return false, "", fmt.Errorf("to ascii: %w", err)
	}
	if len(ascii) > 253 || !asciiName.MatchString(ascii) {
		return false, "", fmt.Errorf("invalid name %q", ascii)
	}
	return indic, ascii, nil
}

// UnderIndiaIDNTLD reports whether an ASCII name ends in one of India's
// IDN TLDs (already blocked by the regex).
func UnderIndiaIDNTLD(ascii string) bool {
	i := strings.LastIndexByte(ascii, '.')
	tld := ascii[i+1:]
	for _, t := range IndiaIDNTLDs {
		if tld == t {
			return true
		}
	}
	return false
}

// Runner runs a command and returns its stdout.
type Runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

type Config struct {
	Docker    string
	Container string
	Window    time.Duration
	Max       int
	DryRun    bool
	Comment   string
	Now       func() time.Time
}

func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Run does one pass and returns the names it added (or would add).
func Run(cfg Config, run Runner, log io.Writer) ([]string, error) {
	since := cfg.Now().Add(-cfg.Window).Unix()
	q := fmt.Sprintf("SELECT DISTINCT domain FROM queries WHERE timestamp >= %d AND "+
		"(domain LIKE '%%xn--%%' OR length(domain) <> length(CAST(domain AS BLOB)));", since)
	out, err := run(cfg.Docker, "exec", cfg.Container, "pihole-FTL", "sqlite3", "-readonly",
		"/etc/pihole/pihole-FTL.db", q)
	if err != nil {
		return nil, fmt.Errorf("read query log: %w", err)
	}
	denied, err := run(cfg.Docker, "exec", cfg.Container, "pihole-FTL", "sqlite3", "-readonly",
		"/etc/pihole/gravity.db", "SELECT domain FROM domainlist WHERE type = 1;")
	if err != nil {
		return nil, fmt.Errorf("read deny list: %w", err)
	}
	have := map[string]bool{}
	for _, d := range lines(denied) {
		have[strings.ToLower(d)] = true
	}
	seen := map[string]bool{}
	var add []string
	for _, name := range lines(out) {
		indic, ascii, err := Classify(name)
		if err != nil {
			fmt.Fprintf(log, "skip %q: %v\n", name, err)
			continue
		}
		if !indic || have[ascii] || seen[ascii] || UnderIndiaIDNTLD(ascii) {
			continue
		}
		seen[ascii] = true
		add = append(add, ascii)
	}
	sort.Strings(add)
	if len(add) > cfg.Max {
		fmt.Fprintf(log, "found %d names, adding only the first %d (--max)\n", len(add), cfg.Max)
		add = add[:cfg.Max]
	}
	for _, a := range add {
		fmt.Fprintf(log, "indic: %s\n", a)
	}
	if cfg.DryRun || len(add) == 0 {
		return add, nil
	}
	for i := 0; i < len(add); i += 50 {
		j := min(i+50, len(add))
		args := append([]string{"exec", cfg.Container, "pihole", "deny", "-q", "--comment", cfg.Comment}, add[i:j]...)
		if _, err := run(cfg.Docker, args...); err != nil {
			return add[:i], fmt.Errorf("pihole deny: %w", err)
		}
	}
	return add, nil
}

func main() {
	cfg := Config{Now: time.Now}
	flag.StringVar(&cfg.Docker, "docker", "docker", "docker binary")
	flag.StringVar(&cfg.Container, "container", "pihole", "Pi-hole container name")
	flag.DurationVar(&cfg.Window, "window", 15*time.Minute, "how far back to read queries")
	flag.IntVar(&cfg.Max, "max", 200, "most names to add in one run")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "print what would be added, change nothing")
	flag.StringVar(&cfg.Comment, "comment", "india-lang indic-idn-guard", "comment on added deny entries")
	flag.Parse()
	if cfg.Max < 1 || cfg.Window <= 0 || cfg.Comment == "" {
		fmt.Fprintln(os.Stderr, "invalid flags")
		os.Exit(2)
	}
	added, err := Run(cfg, execRunner, os.Stdout)
	verb := "added"
	if cfg.DryRun {
		verb = "would add"
	}
	fmt.Printf("indic-idn-guard: %s %d name(s)\n", verb, len(added))
	if err != nil {
		fmt.Fprintln(os.Stderr, "indic-idn-guard:", err)
		os.Exit(1)
	}
}
