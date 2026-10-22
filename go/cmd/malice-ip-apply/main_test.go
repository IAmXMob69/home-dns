package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestKeep(t *testing.T) {
	in := "# c\n\n1.2.3.4\n5.6.7.9/24\n10.1.0.0/16\n100.100.0.1\n8.8.0.0/255.255.0.0\n2001:db8::/32\n224.1.1.1\n01.2.3.4\n9.9.9.9/33\n 4.4.4.0/22 \n0.0.0.0/0\n"
	got := Keep(in)
	want := []string{"1.2.3.4/32", "5.6.7.0/24", "8.8.0.0/16", "4.4.4.0/22"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestElems(t *testing.T) {
	xs := make([]string, 81)
	for i := range xs {
		xs[i] = "1.1.1.1/32"
	}
	e := elems(xs, 40)
	if strings.Count(e, "\n") != 2 || !strings.HasPrefix(e, "      1.1.1.1/32, ") || !strings.HasSuffix(e, ",\n      1.1.1.1/32") {
		t.Fatalf("%q", e)
	}
	if !strings.Contains(Ruleset([]string{"1.2.3.0/24"}), "elements = {\n      1.2.3.0/24\n    }") {
		t.Fatal("ruleset")
	}
}
