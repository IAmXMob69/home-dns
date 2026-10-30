// Package cidr is the strict IP prefix validator shared by the firewall
// tools. lib/cidr.sh is the Bash mirror; both must accept and reject the
// same lines (tests/fixtures/cidr-cases.tsv is checked against both).
//
// Policy, per line:
//   - Surrounding ASCII whitespace (space, tab, CR, LF, VT, FF) is trimmed.
//   - In a list, blank lines and lines starting with '#' are skipped.
//     Inline comments ("1.2.3.0/24 # x") are rejected.
//   - The line must be ADDRESS/BITS. Bare addresses are rejected.
//   - BITS is decimal without leading zeros, 1..32 (IPv4) or 1..128 (IPv6).
//     /0 is rejected: it would match every address.
//   - Host bits must be zero (10.0.0.1/8 is rejected, not rounded down).
//   - IPv4: four decimal octets 0..255, no leading zeros (nft reads
//     010.0.0.0 as octal 8.0.0.0).
//   - IPv6: hex groups (either case), at most one "::". Zone ids ("%eth0"),
//     embedded dotted IPv4 ("::1.2.3.4") and IPv4-mapped addresses
//     (::ffff:0:0/96) are rejected.
//   - Families never mix: an IPv6 prefix in an IPv4 list is an error.
//
// Accepted lines are returned trimmed but otherwise as written; nft does
// its own canonical formatting. Duplicates and overlaps are allowed (the
// sets use auto-merge).
package cidr

import (
	"fmt"
	"net/netip"
	"strings"
)

// Family is the address family a list must contain.
type Family int

const (
	V4 Family = 4
	V6 Family = 6
)

const ws = " \t\r\n\v\f"

func (f Family) String() string {
	if f == V6 {
		return "IPv6"
	}
	return "IPv4"
}

func decimal(s string, max int) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, n <= max
}

// Validate checks one prefix (already free of comments) and returns it trimmed.
func Validate(line string, fam Family) (string, error) {
	s := strings.Trim(line, ws)
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%q is not a valid %s prefix: %s", s, fam, why)
	}
	addr, bitsS, ok := strings.Cut(s, "/")
	if !ok {
		return bad("missing /length")
	}
	max := 32
	if fam == V6 {
		max = 128
	}
	bits, ok := decimal(bitsS, max)
	if !ok {
		return bad(fmt.Sprintf("length must be 1-%d without leading zeros", max))
	}
	if bits == 0 {
		return bad("/0 would match every address")
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		isDigit := c >= '0' && c <= '9'
		isHex := isDigit || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if fam == V4 && !isDigit && c != '.' {
			return bad("unexpected character")
		}
		if fam == V6 && !isHex && c != ':' {
			return bad("unexpected character")
		}
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return bad("bad address")
	}
	if fam == V4 && !a.Is4() || fam == V6 && !a.Is6() {
		return bad("wrong address family")
	}
	if a.Is4In6() {
		return bad("IPv4-mapped address")
	}
	p := netip.PrefixFrom(a, bits)
	if p.Masked() != p {
		return bad("host bits set")
	}
	return s, nil
}

// ParseList validates a whole list. Any invalid line rejects the list; an
// empty list (only comments/blank lines) is an error too.
func ParseList(data []byte, fam Family) ([]string, error) {
	var out []string
	for i, line := range strings.Split(string(data), "\n") {
		t := strings.Trim(line, ws)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		p, err := Validate(t, fam)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s prefixes", fam)
	}
	return out, nil
}
