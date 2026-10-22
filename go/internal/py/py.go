// Package py holds small helpers that reproduce Python output byte-for-byte
// (float repr, json.dumps, str.splitlines/strip, dict ordering).
package py

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Float formats f like Python's repr(float).
func Float(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	a := math.Abs(f)
	if a != 0 && (a < 1e-4 || a >= 1e16) {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		return s
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// Map is an insertion-ordered map with Python dict semantics: re-assigning a
// key keeps its original position.
type Map struct {
	Keys []string
	Vals map[string]any
}

func NewMap() *Map { return &Map{Vals: map[string]any{}} }

func (m *Map) Set(k string, v any) *Map {
	if _, ok := m.Vals[k]; !ok {
		m.Keys = append(m.Keys, k)
	}
	m.Vals[k] = v
	return m
}

func (m *Map) Get(k string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.Vals[k]
	return v, ok
}

// GetOr returns the value for k, or def when missing (dict.get(k, def)).
func (m *Map) GetOr(k string, def any) any {
	if v, ok := m.Get(k); ok {
		return v
	}
	return def
}

func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.Keys)
}

// MarshalJSON keeps key order (Go-side requests).
func (m *Map) MarshalJSON() ([]byte, error) { return []byte(Dumps(m, false)), nil }

// O builds a Map from alternating key, value pairs.
func O(kv ...any) *Map {
	m := NewMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

// Decode parses JSON keeping object key order (objects become *Map,
// numbers json.Number).
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("Extra data")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := NewMap()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				m.Set(kt.(string), v)
			}
			_, err = dec.Token()
			return m, err
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err = dec.Token()
			return arr, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return tok, nil
	}
}

// Dumps renders v like Python json.dumps (ensure_ascii). compact selects
// separators=(",", ":"); otherwise (", ", ": ").
func Dumps(v any, compact bool) string {
	var b strings.Builder
	item, kv := ", ", ": "
	if compact {
		item, kv = ",", ":"
	}
	dump(&b, v, item, kv)
	return b.String()
}

func dump(b *strings.Builder, v any, item, kv string) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		switch {
		case math.IsNaN(t):
			b.WriteString("NaN")
		case math.IsInf(t, 1):
			b.WriteString("Infinity")
		case math.IsInf(t, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(Float(t))
		}
	case json.Number:
		if i, err := t.Int64(); err == nil {
			b.WriteString(strconv.FormatInt(i, 10))
		} else if f, err := t.Float64(); err == nil {
			dump(b, f, item, kv)
		} else {
			b.WriteString(t.String())
		}
	case string:
		b.WriteString(QuoteJSON(t))
	case *Map:
		b.WriteByte('{')
		for i, k := range t.Keys {
			if i > 0 {
				b.WriteString(item)
			}
			b.WriteString(QuoteJSON(k))
			b.WriteString(kv)
			dump(b, t.Vals[k], item, kv)
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m := NewMap()
		for _, k := range keys {
			m.Set(k, t[k])
		}
		dump(b, m, item, kv)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteString(item)
			}
			dump(b, e, item, kv)
		}
		b.WriteByte(']')
	case []string:
		arr := make([]any, len(t))
		for i, s := range t {
			arr[i] = s
		}
		dump(b, arr, item, kv)
	case []int:
		arr := make([]any, len(t))
		for i, s := range t {
			arr[i] = s
		}
		dump(b, arr, item, kv)
	case []float64:
		arr := make([]any, len(t))
		for i, s := range t {
			arr[i] = s
		}
		dump(b, arr, item, kv)
	default:
		bs, _ := json.Marshal(t)
		b.Write(bs)
	}
}

// QuoteJSON quotes s like Python json.dumps with ensure_ascii=True.
func QuoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(&b, `\u%04x`, r)
			case r < 0x7f || r == 0x7f:
				b.WriteRune(r)
			case r == utf8.RuneError:
				b.WriteString(`\ufffd`)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// SplitLines mimics str.splitlines().
func SplitLines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	cur := []rune{}
	_ = start
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			out = append(out, string(cur))
			cur = cur[:0]
		case '\r':
			out = append(out, string(cur))
			cur = cur[:0]
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
		default:
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func isPySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Strip mimics str.strip().
func Strip(s string) string { return strings.TrimFunc(s, isPySpace) }

// Truthy mimics bool(x) for decoded JSON values.
func Truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case *Map:
		return t.Len() > 0
	}
	return true
}

// ToFloat mimics float(x).
func ToFloat(v any) (float64, error) {
	switch t := v.(type) {
	case bool:
		if t {
			return 1, nil
		}
		return 0, nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case float64:
		return t, nil
	case json.Number:
		return t.Float64()
	case string:
		f, err := strconv.ParseFloat(Strip(t), 64)
		if err != nil {
			return 0, fmt.Errorf("could not convert string to float: %s", Repr(t))
		}
		return f, nil
	case []byte:
		return ToFloat(string(t))
	case nil:
		return 0, fmt.Errorf("float() argument must be a string or a real number, not 'NoneType'")
	}
	return 0, fmt.Errorf("float() argument must be a string or a real number, not '%T'", v)
}

// ToInt mimics int(x) loosely (numbers truncate, numeric strings parse).
func ToInt(v any) int {
	switch t := v.(type) {
	case bool:
		if t {
			return 1
		}
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
		f, _ := t.Float64()
		return int(f)
	case string:
		i, _ := strconv.Atoi(Strip(t))
		return i
	}
	return 0
}

// Str mimics str(x) for decoded JSON values.
func Str(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return strconv.FormatInt(i, 10)
		}
		f, _ := t.Float64()
		return Float(f)
	case float64:
		return Float(t)
	case int:
		return strconv.Itoa(t)
	}
	return Repr(v)
}

// Repr mimics repr(x) for decoded JSON values.
func Repr(v any) string {
	switch t := v.(type) {
	case string:
		q := "'"
		if strings.Contains(t, "'") && !strings.Contains(t, `"`) {
			q = `"`
		}
		var b strings.Builder
		b.WriteString(q)
		for _, r := range t {
			switch {
			case r == '\\':
				b.WriteString(`\\`)
			case string(r) == q:
				b.WriteString(`\` + q)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\t':
				b.WriteString(`\t`)
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(&b, `\x%02x`, r)
			default:
				b.WriteRune(r)
			}
		}
		b.WriteString(q)
		return b.String()
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *Map:
		parts := make([]string, 0, t.Len())
		for _, k := range t.Keys {
			parts = append(parts, Repr(k)+": "+Repr(t.Vals[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return Str(v)
}

// DumpsIndent renders v like json.dumps(v, indent=n) (ensure_ascii).
func DumpsIndent(v any, n int) string {
	var b strings.Builder
	dumpIndent(&b, v, n, 0)
	return b.String()
}

func dumpIndent(b *strings.Builder, v any, n, lvl int) {
	pad := func(l int) { b.WriteString("\n" + strings.Repeat(" ", n*l)) }
	switch t := v.(type) {
	case *Map:
		if len(t.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range t.Keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pad(lvl + 1)
			b.WriteString(QuoteJSON(k) + ": ")
			dumpIndent(b, t.Vals[k], n, lvl+1)
		}
		pad(lvl)
		b.WriteByte('}')
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			pad(lvl + 1)
			dumpIndent(b, e, n, lvl+1)
		}
		pad(lvl)
		b.WriteByte(']')
	default:
		dump(b, v, ", ", ": ")
	}
}
