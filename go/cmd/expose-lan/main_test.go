package main

import "testing"

func TestPrefixLen(t *testing.T) {
	for in, want := range map[string]string{"198.51.100.0/24": "24", "203.0.113.0/26": "26", "198.51.100.0": "24"} {
		if got := prefixLen(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestLanRules(t *testing.T) {
	if len(lanRules("198.51.100.0/24", "")) != 4 || len(lanRules("198.51.100.0/24", "2001:db8::/64")) != 6 {
		t.Fatal("rule count")
	}
}
