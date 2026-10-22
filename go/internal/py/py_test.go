package py

import (
	"reflect"
	"testing"
)

func TestFloat(t *testing.T) {
	for f, want := range map[float64]string{0: "0.0", 1: "1.0", 1234567: "1234567.0", 0.5: "0.5",
		1e16: "1e+16", 1.5e-5: "1.5e-05", 0.0001: "0.0001", 123.456: "123.456", -2: "-2.0"} {
		if got := Float(f); got != want {
			t.Errorf("%v: got %s want %s", f, got, want)
		}
	}
}

func TestDumps(t *testing.T) {
	m := O("ts", "2026-10-22T06:00:00-04:00", "event", "check", "mode", "pihole", "loopback", true,
		"fail", 0, "n", nil, "u", "é<>&/\x01")
	want := `{"ts":"2026-10-22T06:00:00-04:00","event":"check","mode":"pihole","loopback":true,"fail":0,"n":null,"u":"\u00e9<>&/\u0001"}`
	if got := Dumps(m, true); got != want {
		t.Fatalf("got %s", got)
	}
	if got := Dumps(O("a", 1, "b", []any{1, "x"}), false); got != `{"a": 1, "b": [1, "x"]}` {
		t.Fatalf("got %s", got)
	}
}

func TestDecodeOrder(t *testing.T) {
	v, err := Decode([]byte(`{"z":1,"a":{"y":2,"b":3},"z":4}`))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(*Map)
	if !reflect.DeepEqual(m.Keys, []string{"z", "a"}) || Str(m.Vals["z"]) != "4" {
		t.Fatalf("%v", m.Keys)
	}
	if !reflect.DeepEqual(m.Vals["a"].(*Map).Keys, []string{"y", "b"}) {
		t.Fatal("inner order")
	}
}

func TestSplitStrip(t *testing.T) {
	got := SplitLines("a\r\nb\rc\n\nd")
	if !reflect.DeepEqual(got, []string{"a", "b", "c", "", "d"}) {
		t.Fatalf("%q", got)
	}
	if Strip(" \t x \x1f\n") != "x" {
		t.Fatal("strip")
	}
}

func TestRepr(t *testing.T) {
	v, _ := Decode([]byte(`[{"item":"a.com","error":"x"}]`))
	if got := Repr(v); got != `[{'item': 'a.com', 'error': 'x'}]` {
		t.Fatal(got)
	}
	if Repr("it's") != `"it's"` {
		t.Fatal(Repr("it's"))
	}
}
