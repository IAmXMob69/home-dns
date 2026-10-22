package main

import (
	"strings"
	"testing"
)

func TestBlocks(t *testing.T) {
	v4 := v4Block("198.51.100.0/24")
	if !strings.Contains(v4, "-A DOCKER-USER -s 198.51.100.0/24 -j RETURN") {
		t.Fatal(v4)
	}
	if r := rulesOf(v4); len(r) != 8 || r[len(r)-1][1] != "DROP" {
		t.Fatalf("v4 rules: %v", r)
	}
	if strings.Contains(v6Block(""), "2001:db8") || len(rulesOf(v6Block(""))) != 8 {
		t.Fatal("empty LAN_IPV6_CIDR must add no LAN rule")
	}
	if r := rulesOf(v6Block("2001:db8:1::/64")); len(r) != 9 || r[5][1] != "2001:db8:1::/64" {
		t.Fatalf("v6 rules: %v", r)
	}
}

func TestUfwRules(t *testing.T) {
	if n := len(ufwRules("198.51.100.0/24", "")); n != 9 {
		t.Fatalf("got %d rules", n)
	}
	if n := len(ufwRules("198.51.100.0/24", "2001:db8:1::/64")); n != 11 {
		t.Fatalf("got %d rules", n)
	}
}
