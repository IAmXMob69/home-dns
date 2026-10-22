// Package dnswire builds and parses the minimal DNS messages the probes use.
package dnswire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// EncodeLabel mirrors Python's label.encode("idna").
func EncodeLabel(label string) ([]byte, error) {
	if label == "" {
		return nil, nil
	}
	if isASCII(label) {
		if len(label) >= 64 {
			// Python 3.14 wording.
			return nil, fmt.Errorf("'idna' codec can't encode characters in position 0-%d: label too long", len(label)-1)
		}
		return []byte(label), nil
	}
	a, err := idnaProfile.ToASCII(label)
	if err != nil {
		return nil, err
	}
	if len(a) == 0 || len(a) >= 64 {
		return nil, errors.New("label empty or too long")
	}
	return []byte(a), nil
}

// EncodeName mirrors dns-probe.py encode_name (strict=true adds the >63 check).
func EncodeName(name string) ([]byte, error) {
	var out []byte
	for _, label := range strings.Split(strings.TrimRight(name, "."), ".") {
		part, err := EncodeLabel(label)
		if err != nil {
			return nil, err
		}
		if len(part) > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}
	return append(out, 0), nil
}

func randID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// BuildQuery returns a recursion-desired query for host/qtype (class IN).
func BuildQuery(host string, qtype uint16) ([]byte, error) {
	name, err := EncodeName(host)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 12, 12+len(name)+4)
	binary.BigEndian.PutUint16(msg[0:], randID())
	binary.BigEndian.PutUint16(msg[2:], 0x0100)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, name...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	return msg, nil
}

// ParseHeader returns (rcode, ancount).
func ParseHeader(data []byte) (int, int, error) {
	if len(data) < 12 {
		return 0, 0, errors.New("short DNS response")
	}
	return int(data[3] & 0x0F), int(binary.BigEndian.Uint16(data[6:8])), nil
}

func skipName(data []byte, off int) (int, error) {
	for {
		if off >= len(data) {
			return 0, errors.New("truncated DNS name")
		}
		l := int(data[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(data) {
				return 0, errors.New("truncated compression pointer")
			}
			return off + 2, nil
		}
		off += 1 + l
	}
}

// ParseAnswers returns A/AAAA address strings from the answer section.
func ParseAnswers(data []byte) ([]string, error) {
	if len(data) < 12 {
		return nil, errors.New("short DNS response")
	}
	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	off, err := skipName(data, 12)
	if err != nil {
		return nil, err
	}
	off += 4
	addrs := []string{}
	for i := 0; i < ancount; i++ {
		off, err = skipName(data, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(data) {
			return nil, errors.New("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(data[off:])
		rdlen := int(binary.BigEndian.Uint16(data[off+8:]))
		off += 10
		end := off + rdlen
		if end > len(data) {
			end = len(data)
		}
		rdata := data[off:end]
		off += rdlen
		switch {
		case rtype == 1 && rdlen == 4:
			if len(rdata) != 4 {
				return nil, fmt.Errorf("Packed address must be 4 bytes long")
			}
			addrs = append(addrs, netip.AddrFrom4([4]byte(rdata)).String())
		case rtype == 28 && rdlen == 16:
			if len(rdata) != 16 {
				return nil, fmt.Errorf("Packed address must be 16 bytes long")
			}
			addrs = append(addrs, netip.AddrFrom16([16]byte(rdata)).String())
		}
	}
	return addrs, nil
}

// IsBlockAddr reports 0.0.0.0 or ::.
func IsBlockAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return a.IsUnspecified() && a.Zone() == ""
}
