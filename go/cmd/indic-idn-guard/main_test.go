package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/idna"
)

func puny(t *testing.T, s string) string {
	t.Helper()
	a, err := idna.Punycode.ToASCII(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in    string
		indic bool
	}{
		{"google.com", false},
		{"GOOGLE.COM.", false},
		{"linkedin.com", false},
		{"namaste.com", false},                    // transliterated Hindi: not detectable
		{puny(t, "bücher.de"), false},             // Latin with diacritics
		{puny(t, "مثال.com"), false},              // Arabic script is out of scope
		{puny(t, "اردو.com"), false},              // Urdu, Arabic script
		{puny(t, "例子.com"), false},                // Han
		{puny(t, "пример.com"), false},            // Cyrillic
		{puny(t, "උදාහරණ.com"), false},            // Sinhala
		{puny(t, "उदाहरण.com"), true},             // Devanagari
		{puny(t, "উদাহরণ.com"), true},             // Bengali
		{puny(t, "ਉਦਾਹਰਨ.com"), true},             // Gurmukhi
		{puny(t, "ઉદાહરણ.com"), true},             // Gujarati
		{puny(t, "ଉଦାହରଣ.com"), true},             // Oriya
		{puny(t, "உதாரணம்.com"), true},            // Tamil
		{puny(t, "ఉదాహరణ.com"), true},             // Telugu
		{puny(t, "ಉದಾಹರಣೆ.com"), true},            // Kannada
		{puny(t, "ഉദാഹരണം.com"), true},            // Malayalam
		{puny(t, "ᱥᱟᱱᱛᱟᱲᱤ.com"), true},            // Ol Chiki
		{puny(t, "ꯃꯤꯇꯩ.com"), true},               // Meetei Mayek
		{puny(t, "www.उदाहरण.example.com"), true}, // any label counts
		{"xn--11b5bs3a9aj6g.xn--h2brj9c", true},   // परीक्षा.भारत
		{"उदाहरण.com", true},                      // raw UTF-8 query
	}
	for _, c := range cases {
		indic, ascii, err := Classify(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if indic != c.indic {
			t.Errorf("%s: indic=%v want %v", c.in, indic, c.indic)
		}
		if strings.ContainsFunc(ascii, func(r rune) bool { return r > 127 }) {
			t.Errorf("%s: ascii form %q not ASCII", c.in, ascii)
		}
	}
}

func TestIsIndicRuneVedic(t *testing.T) {
	for _, r := range []rune{0x1CD0, 0x1CF2, 0xA8F2, 0x11B00, 0xAAE0} {
		if !IsIndicRune(r) {
			t.Errorf("%U should be Indic", r)
		}
	}
	for _, r := range []rune{'a', 'Z', '0', 0x0627, 0x0D85, 0x4E00} {
		if IsIndicRune(r) {
			t.Errorf("%U should not be Indic", r)
		}
	}
}

func TestClassifyRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "a;rm -rf.com", "xn--zz-.com", "a b.com", "-x.com",
		"$(id).com", "a..b", strings.Repeat("a", 64) + ".com"} {
		if _, _, err := Classify(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestIndiaTLDsDecodeToIndianNames(t *testing.T) {
	for _, tld := range IndiaIDNTLDs {
		u, err := idna.Punycode.ToUnicode(tld)
		if err != nil || u == tld {
			t.Errorf("%s: %v", tld, err)
		}
		if !UnderIndiaIDNTLD("x." + tld) {
			t.Errorf("%s not matched", tld)
		}
	}
	if UnderIndiaIDNTLD("x.xn--xkc2al3hye2a") { // Sri Lanka, not India
		t.Error("Sri Lanka TLD must not match")
	}
}

type fake struct {
	queries, denied string
	calls           [][]string
}

func (f *fake) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "pihole-FTL.db"):
		return []byte(f.queries), nil
	case strings.Contains(joined, "gravity.db"):
		return []byte(f.denied), nil
	}
	return nil, nil
}

func TestRun(t *testing.T) {
	dev := puny(t, "उदाहरण.com")
	tam := puny(t, "உதாரணம்.net")
	f := &fake{
		queries: strings.Join([]string{"google.com", dev, tam, "XN--11B5BS3A9AJ6G.XN--H2BRJ9C",
			puny(t, "مثال.com"), "xn--zz-.com", dev}, "\n"),
		denied: tam + "\n",
	}
	cfg := Config{Docker: "docker", Container: "pihole", Window: time.Minute, Max: 10,
		Comment: "india-lang indic-idn-guard", Now: func() time.Time { return time.Unix(1000, 0) }}
	var log bytes.Buffer
	added, err := Run(cfg, f.run, &log)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != dev {
		t.Fatalf("added %v, want [%s]", added, dev)
	}
	last := f.calls[len(f.calls)-1]
	want := []string{"docker", "exec", "pihole", "pihole", "deny", "-q", "--comment", "india-lang indic-idn-guard", dev}
	if strings.Join(last, "|") != strings.Join(want, "|") {
		t.Fatalf("deny call %v, want %v", last, want)
	}
	if !strings.Contains(strings.Join(f.calls[0], " "), "timestamp >= 940") {
		t.Fatalf("window not applied: %v", f.calls[0])
	}
}

func TestRunDryRunAndMax(t *testing.T) {
	var names []string
	for _, s := range []string{"क.com", "ख.com", "ग.com"} {
		names = append(names, puny(t, s))
	}
	f := &fake{queries: strings.Join(names, "\n")}
	cfg := Config{Docker: "docker", Container: "pihole", Window: time.Minute, Max: 2,
		DryRun: true, Comment: "c", Now: time.Now}
	added, err := Run(cfg, f.run, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("max not applied: %v", added)
	}
	if len(f.calls) != 2 {
		t.Fatalf("dry run must not call pihole deny: %v", f.calls)
	}
}
