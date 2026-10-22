package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSettings(t *testing.T) {
	set := map[string]string{"GEOLOCK_ENABLED": "0", "GEOLOCK_MODE": "allow"}
	var warn bytes.Buffer
	err := ParseSettings("s.env", []byte("# c\n\nGEOLOCK_ENABLED=1\r\nGEOLOCK_ALLOW_COUNTRIES=\"US,DE\"  \nFOO=bar\nGEOLOCK_PORTS=53,853"), set, &warn)
	if err != nil || set["GEOLOCK_ENABLED"] != "1" || set["GEOLOCK_ALLOW_COUNTRIES"] != "US,DE" || set["GEOLOCK_PORTS"] != "53,853" {
		t.Fatalf("%v %v", err, set)
	}
	if warn.String() != "geolock: ignoring unknown key FOO\n" {
		t.Fatal(warn.String())
	}
	for in, msg := range map[string]string{
		"GEOLOCK_ENABLED=2":      "GEOLOCK_ENABLED must be 0 or 1",
		"x=1":                    "s.env:1: expected KEY=value",
		"GEOLOCK_PORTS=53, 853":  "s.env:1: expected KEY=value",
		"GEOLOCK_MODE=block":     "GEOLOCK_MODE must be allow or deny",
		"GEOLOCK_MAX_AGE_DAYS=a": "GEOLOCK_MAX_AGE_DAYS must be a number",
	} {
		if err := ParseSettings("s.env", []byte(in), map[string]string{}, &warn); err == nil || err.Error() != msg {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestCodes(t *testing.T) {
	c, err := Codes("US,de,,GB")
	if err != nil || strings.Join(c, " ") != "us de gb" {
		t.Fatal(c, err)
	}
	if _, err := Codes("USA"); err == nil || err.Error() != "bad country code 'usa' (use ISO 3166-1 alpha-2)" {
		t.Fatal(err)
	}
}

func TestRuleset(t *testing.T) {
	r := string(Ruleset("allow", "53, 853", true, "user.slice/app.slice", [][]byte{[]byte("1.0.0.0/24\n"), []byte("2.0.0.0/8")}))
	for _, want := range []string{
		"    elements = {\n      1.0.0.0/24,\n      2.0.0.0/8,    }\n",
		"th dport { 53, 853 } ip saddr != @listed4 counter drop",
		"ct original proto-dst { 53, 853 } ip saddr != @listed4 counter drop",
		`socket cgroupv2 level 2 "user.slice/app.slice" ip daddr != @listed4 drop`,
		`"system.slice/tailscaled.service" accept`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q", want)
		}
	}
	d := string(Ruleset("deny", "53", false, "user.slice/app.slice", nil))
	if strings.Contains(d, "cgroupv2") || !strings.Contains(d, "th sport { 53 } ip daddr @listed4 counter drop") {
		t.Fatal(d)
	}
}

func TestFilterList(t *testing.T) {
	out, m, v := FilterList([]byte("# hdr\n1.2.3.0/24\n2.0.0.0/8\n"))
	if string(out) != "1.2.3.0/24\n2.0.0.0/8\n" || !m || !v {
		t.Fatal(string(out), m, v)
	}
	if _, _, v := FilterList([]byte("1.2.3.4\n")); v {
		t.Fatal("bare IP is not a CIDR")
	}
	if _, m, _ := FilterList([]byte("<html>")); m {
		t.Fatal("no match")
	}
}
