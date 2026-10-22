package dnswire

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEncodeName(t *testing.T) {
	got, err := EncodeName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("\x07example\x03com\x00"); !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	if _, err := EncodeName(string(bytes.Repeat([]byte("a"), 64)) + ".com"); err == nil {
		t.Fatal("want error for 64-byte label")
	}
	got, _ = EncodeName("münchen.de")
	if !bytes.Contains(got, []byte("xn--mnchen-3ya")) {
		t.Fatalf("idna: %q", got)
	}
	// Python: "".encode("idna") == b"" so an empty host is two zero bytes.
	got, _ = EncodeName("")
	if !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("empty: %q", got)
	}
}

func TestBuildQuery(t *testing.T) {
	q, err := BuildQuery("example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(q[2:]) != "01000001000000000000076578616d706c6503636f6d0000010001" {
		t.Fatalf("query %x", q)
	}
}

func mkResp(rcode byte, rrs ...[]byte) []byte {
	b := []byte{0x12, 0x34, 0x81, 0x80 | rcode, 0, 1, 0, byte(len(rrs)), 0, 0, 0, 0}
	b = append(b, []byte("\x07example\x03com\x00\x00\x01\x00\x01")...)
	for _, rr := range rrs {
		b = append(b, rr...)
	}
	return b
}

func TestParse(t *testing.T) {
	a1 := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14}
	a2 := []byte{0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x26, 0x06, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	cname := append([]byte{0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2}, 0xc0, 0x0c)
	data := mkResp(0, cname, a1, a2)
	rc, an, err := ParseHeader(data)
	if err != nil || rc != 0 || an != 3 {
		t.Fatalf("header %d %d %v", rc, an, err)
	}
	addrs, err := ParseAnswers(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"93.184.215.14", "2606:2800::1"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("addrs %v", addrs)
	}
	if _, err := ParseAnswers(data[:len(data)-30]); err == nil {
		t.Fatal("want truncation error")
	}
	if _, _, err := ParseHeader([]byte{1, 2}); err == nil || err.Error() != "short DNS response" {
		t.Fatal(err)
	}
	rc, _, _ = ParseHeader(mkResp(3))
	if rc != 3 {
		t.Fatal(rc)
	}
}

func TestBlockAddr(t *testing.T) {
	for s, want := range map[string]bool{"0.0.0.0": true, "::": true, "1.2.3.4": false, "x": false, "::1": false} {
		if IsBlockAddr(s) != want {
			t.Errorf("%s", s)
		}
	}
}
