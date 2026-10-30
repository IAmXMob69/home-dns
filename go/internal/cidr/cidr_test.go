package cidr

import (
	"bufio"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../../tests/fixtures/cidr-cases.tsv"

type tcase struct {
	fam  Family
	ok   bool
	in   string
	note string
}

func famName(f Family) string {
	if f == V6 {
		return "v6"
	}
	return "v4"
}

func unescape(s string) string {
	return strings.NewReplacer(`\\`, `\`, `\t`, "\t", `\r`, "\r").Replace(s)
}

func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\r", `\r`).Replace(s)
}

func loadCases(t *testing.T) []tcase {
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cs []tcase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		p := strings.SplitN(line, "\t", 4)
		if len(p) < 3 || (p[0] != "v4" && p[0] != "v6") || (p[1] != "ok" && p[1] != "bad") {
			t.Fatalf("bad fixture row %q", line)
		}
		fam := V4
		if p[0] == "v6" {
			fam = V6
		}
		note := ""
		if len(p) == 4 {
			note = p[3]
		}
		cs = append(cs, tcase{fam, p[1] == "ok", unescape(p[2]), note})
	}
	if len(cs) < 50 {
		t.Fatalf("only %d fixture rows", len(cs))
	}
	return cs
}

func TestValidateFixture(t *testing.T) {
	for _, c := range loadCases(t) {
		got, err := Validate(c.in, c.fam)
		if (err == nil) != c.ok {
			t.Errorf("%s %q (%s): ok=%v err=%v", famName(c.fam), c.in, c.note, c.ok, err)
		}
		if err == nil && got != strings.Trim(c.in, ws) {
			t.Errorf("%q: returned %q, want it trimmed only", c.in, got)
		}
	}
}

func TestParseList(t *testing.T) {
	got, err := ParseList([]byte("# Country: X\n#\n\n1.2.3.0/24\r\n  2.0.0.0/8\n1.2.3.0/24\n"), V4)
	if err != nil || strings.Join(got, ",") != "1.2.3.0/24,2.0.0.0/8,1.2.3.0/24" {
		t.Fatal(got, err)
	}
	for in, want := range map[string]string{
		"# only\n\n":           "no IPv4 prefixes",
		"1.2.3.0/24\nbogus\n":  "line 2:",
		"1.2.3.0/24\n::/128\n": "line 2:",
	} {
		if _, err := ParseList([]byte(in), V4); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := ParseList([]byte("2001:db8::/32\n"), V6); err != nil {
		t.Fatal(err)
	}
}

// bashVerdicts runs lib/cidr.sh cidr_valid over a fixture-format file and
// returns "ok"/"bad" per data row.
func bashVerdicts(t *testing.T, path string) []string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	lib, _ := filepath.Abs("../../../lib/cidr.sh")
	script := `source "$1"
while IFS=$'\t' read -r fam _ in _ || [[ -n "$fam" ]]; do
  [[ -z "$fam" || "$fam" == \#* ]] && continue
  printf -v x '%b' "$in"
  if cidr_valid "$fam" "$x" >/dev/null 2>&1; then echo ok; else echo bad; fi
done < "$2"`
	out, err := exec.Command("bash", "-c", script, "bash", lib, path).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

// TestBashMirror: the Bash fallback must give the same verdict on every row.
func TestBashMirror(t *testing.T) {
	cs := loadCases(t)
	got := bashVerdicts(t, fixture)
	if len(got) != len(cs) {
		t.Fatalf("bash gave %d verdicts for %d rows", len(got), len(cs))
	}
	for i, c := range cs {
		if (got[i] == "ok") != c.ok {
			t.Errorf("bash %s %q (%s): got %s", famName(c.fam), c.in, c.note, got[i])
		}
	}
}

// TestBashMirrorFuzz: deterministic mutations of the fixture inputs must get
// the same verdict from Go and Bash.
func TestBashMirrorFuzz(t *testing.T) {
	cs := loadCases(t)
	r := rand.New(rand.NewSource(1))
	alpha := []byte("0123456789abcdefABCDEF:./%# \t-+x")
	var rows []tcase
	for i := 0; i < 3000; i++ {
		c := cs[r.Intn(len(cs))]
		b := []byte(c.in)
		for n := r.Intn(3) + 1; n > 0; n-- {
			switch op := r.Intn(3); {
			case op == 0 && len(b) > 0:
				b[r.Intn(len(b))] = alpha[r.Intn(len(alpha))]
			case op == 1:
				j := r.Intn(len(b) + 1)
				b = append(b[:j], append([]byte{alpha[r.Intn(len(alpha))]}, b[j:]...)...)
			case len(b) > 0:
				j := r.Intn(len(b))
				b = append(b[:j], b[j+1:]...)
			}
		}
		fam := c.fam
		if r.Intn(4) == 0 {
			fam = V4 + V6 - fam
		}
		_, err := Validate(string(b), fam)
		rows = append(rows, tcase{fam, err == nil, string(b), ""})
	}
	var sb strings.Builder
	for _, c := range rows {
		sb.WriteString(famName(c.fam) + "\tx\t" + escape(c.in) + "\n")
	}
	path := filepath.Join(t.TempDir(), "fuzz.tsv")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got := bashVerdicts(t, path)
	if len(got) != len(rows) {
		t.Fatalf("bash gave %d verdicts for %d rows", len(got), len(rows))
	}
	accepted, bad := 0, 0
	for i, c := range rows {
		if c.ok {
			accepted++
		}
		if (got[i] == "ok") != c.ok {
			bad++
			if bad <= 20 {
				t.Errorf("mismatch %s %q: go ok=%v bash=%s", famName(c.fam), c.in, c.ok, got[i])
			}
		}
	}
	if accepted < 100 {
		t.Fatalf("fuzz too weak: only %d accepted", accepted)
	}
}

// TestBashFilterMirror: cidr_filter and ParseList agree on whole lists.
func TestBashFilterMirror(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	lib, _ := filepath.Abs("../../../lib/cidr.sh")
	cs := loadCases(t)
	for _, fam := range []Family{V4, V6} {
		var good strings.Builder
		good.WriteString("# header\n\n")
		var firstBad string
		for _, c := range cs {
			if c.fam != fam {
				continue
			}
			if c.ok {
				good.WriteString(c.in + "\n")
			} else if firstBad == "" && c.in != "" {
				firstBad = c.in
			}
		}
		for _, list := range []string{good.String(), good.String() + firstBad + "\n", "# none\n", strings.TrimSuffix(good.String(), "\n")} {
			want, werr := ParseList([]byte(list), fam)
			cmd := exec.Command("bash", "-c", `source "$1"; cidr_filter "$2"`, "bash", lib, famName(fam))
			cmd.Stdin = strings.NewReader(list)
			out, berr := cmd.Output()
			if (werr == nil) != (berr == nil) {
				t.Fatalf("%s list: go err=%v bash err=%v\n%s", famName(fam), werr, berr, list)
			}
			if werr == nil && string(out) != strings.Join(want, "\n")+"\n" {
				t.Fatalf("%s list output differs:\ngo:   %q\nbash: %q", famName(fam), want, out)
			}
		}
	}
}
