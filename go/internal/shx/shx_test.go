package shx

import "testing"

func TestHelpers(t *testing.T) {
	if FirstLine("12\r\n34", "0") != "12" || FirstLine("", "0") != "0" {
		t.Fatal("FirstLine")
	}
	if Line("7\r\n826", 2, "0") != "826" || Line("7", 2, "0") != "0" {
		t.Fatal("Line")
	}
	if string(TailLines([]byte("a\nb\nc\n"), 2)) != "b\nc\n" || string(TailLines([]byte("a\nb\nc"), 2)) != "b\nc" || string(TailLines([]byte("a\n"), 5)) != "a\n" {
		t.Fatal("TailLines")
	}
	if QuoteQ("pihole-FTL") != "pihole-FTL" || QuoteQ("a b") != `a\ b` || QuoteQ("") != "''" {
		t.Fatal(QuoteQ("a b"))
	}
	if BashInt("1163675") != 1163675 || BashInt("x") != 0 {
		t.Fatal("BashInt")
	}
}
