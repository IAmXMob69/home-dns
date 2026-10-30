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
	o := Opts{Mode: "allow", Ports: "53, 853", Underlay: true, AppCg: "user.slice/app.slice", Inbound: true, Outbound: true}
	r := string(Ruleset(o, [][]byte{[]byte("1.0.0.0/24\n"), []byte("2.0.0.0/8")}, nil))
	for _, want := range []string{
		"    elements = {\n      1.0.0.0/24,\n      2.0.0.0/8,    }\n",
		"th dport { 53, 853 } ip saddr != @listed4 counter drop",
		"ct original proto-dst { 53, 853 } ip saddr != @listed4 counter drop",
		`meta nfproto ipv6 socket cgroupv2 level 2 "user.slice/app.slice" drop`,
		`socket cgroupv2 level 2 "user.slice/app.slice" ip daddr != @listed4 drop`,
		`"system.slice/tailscaled.service" accept`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"ip6", "pass6", "listed6"} {
		if strings.Contains(r, bad) {
			t.Errorf("IPv6 off but found %q", bad)
		}
	}
	o.Mode, o.Ports, o.Underlay = "deny", "53", false
	d := string(Ruleset(o, nil, nil))
	if strings.Contains(d, "cgroupv2") || !strings.Contains(d, "th sport { 53 } ip daddr @listed4 counter drop") {
		t.Fatal(d)
	}
}

func TestRulesetIPv6(t *testing.T) {
	o := Opts{Mode: "allow", Ports: "53", AppCg: "a.slice", IPv6: true, Inbound: true, Outbound: true}
	r := string(Ruleset(o, [][]byte{[]byte("1.0.0.0/24\n")}, [][]byte{[]byte("2001:db8::/32\n"), nil}))
	for _, want := range []string{
		"  set pass6 {\n    type ipv6_addr\n    flags interval\n    auto-merge\n    elements = { ::1/128, fe80::/10, fc00::/7 }\n  }\n",
		"  set listed6 {\n    type ipv6_addr\n    flags interval\n    auto-merge\n    elements = {\n      2001:db8::/32,\n    }\n  }\n",
		"    ip6 saddr @pass6 accept\n    meta l4proto { tcp, udp } th dport { 53 } ip6 saddr != @listed6 counter drop\n",
		"ct original proto-dst { 53 } ip6 saddr != @listed6 counter drop",
		"    ip daddr @pass4 accept\n    ip6 daddr @pass6 accept\n",
		`socket cgroupv2 level 1 "a.slice" ip6 daddr != @listed6 drop`,
		"th dport { 53 } ip6 daddr != @listed6 counter drop",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(r, "meta nfproto ipv6") {
		t.Error("IPv6 on but the app cgroup still drops all IPv6")
	}
	o.Mode = "deny"
	d := string(Ruleset(o, nil, nil))
	for _, want := range []string{
		"th dport { 53 } ip6 saddr @listed6 counter drop",
		"th sport { 53 } ip6 daddr @listed6 counter drop",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("deny: missing %q", want)
		}
	}
}

func TestRulesetDirections(t *testing.T) {
	in := string(Ruleset(Opts{Mode: "allow", Ports: "53", Inbound: true}, nil, nil))
	if !strings.Contains(in, "chain input") || !strings.Contains(in, "chain forward") || strings.Contains(in, "chain output") {
		t.Fatal(in)
	}
	out := string(Ruleset(Opts{Mode: "allow", Ports: "53", Outbound: true}, nil, nil))
	if strings.Contains(out, "chain input") || strings.Contains(out, "chain forward") || !strings.Contains(out, "chain output") {
		t.Fatal(out)
	}
}

func TestParseExpect(t *testing.T) {
	o := Opts{Mode: "allow", Ports: "53", AppCg: "a.slice", IPv6: true, Inbound: true, Outbound: true}
	e := ParseExpect(Ruleset(o, [][]byte{[]byte("1.2.3.0/24\n4.0.0.0/8\n")}, [][]byte{nil, []byte("2001:db8::/32\n")}))
	if e.Drops["input"] != 2 || e.Drops["forward"] != 2 || e.Drops["output"] != 4 {
		t.Errorf("drops %v", e.Drops)
	}
	if e.First["listed4"] != "1.2.3.0" || e.First["listed6"] != "2001:db8::" || e.First["pass4"] != "" {
		t.Errorf("first %v", e.First)
	}
	e = ParseExpect(Ruleset(Opts{Mode: "deny", Ports: "53", Outbound: true}, nil, nil))
	if _, ok := e.Drops["input"]; ok || e.Drops["output"] != 2 {
		t.Errorf("deny/outbound drops %v", e.Drops)
	}
}

func TestFilterList(t *testing.T) {
	out, err := FilterList([]byte("# Country: X\n#\n1.2.3.0/24\r\n\n 2.0.0.0/8\n"))
	if err != nil || string(out) != "1.2.3.0/24\n2.0.0.0/8\n" {
		t.Fatal(string(out), err)
	}
	for _, bad := range []string{
		"1.2.3.4\n",                // bare IP is not a CIDR
		"<html>\n",                 // error page
		"# only comments\n",        // nothing to load
		"1.2.3.0/24\n10.0.0.1/8\n", // host bits
		"010.0.0.0/8\n",            // nft would read octal 8.0.0.0
		"0.0.0.0/0\n",              // would match everything
		"2001:db8::/32\n",          // wrong family
	} {
		if _, err := FilterList([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckCgroup(t *testing.T) {
	for _, ok := range []string{"user.slice/app.slice", "user.slice/user-4242.slice/user@4242.service/x.slice/a-b.slice"} {
		if CheckCgroup(ok) != nil {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{`a" accept comment "`, "a//b", "a b", "a/", ""} {
		if CheckCgroup(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
