// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

// TestTheNumberSerializationIsRFC8785AppendixB holds FormatECMAScriptNumber to the published table of RFC 8785 Appendix B (the IEEE 754 bit patterns and the text each must yield).
func TestTheNumberSerializationIsRFC8785AppendixB(t *testing.T) {
	for _, c := range []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"}, {0x8000000000000000, "0"}, {0x0000000000000001, "5e-324"}, {0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"}, {0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"}, {0xc340000000000000, "-9007199254740992"}, {0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"}, {0x44b52d02c7e14af6, "1e+23"}, {0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"}, {0x444b1ae4d6e2ef4f, "999999999999999900000"}, {0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"}, {0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"}, {0x41b3de4355555554, "333333333.33333325"}, {0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"}, {0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"}, {0x43143ff3c1cb0959, "1424953923781206.2"},
	} {
		if got := FormatECMAScriptNumber(math.Float64frombits(c.bits)); got != c.want {
			t.Errorf("%016x: %s, want %s", c.bits, got, c.want)
		}
	}
}

// TestTheCanonicalFormIsRFC8785 holds CanonicalizeJSON to the RFC's own examples (section 3.2.2 values and section 3.2.3 member order) and to every rule jcs.go states.
func TestTheCanonicalFormIsRFC8785(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// RFC 8785 section 3.2.2 (the first number is read as the nearest double, as the RFC reads it)
		{`{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", "literals": [null, true, false]}`,
			`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`},
		// RFC 8785 section 3.2.3: members sorted by UTF-16 code units (the emoji's surrogate pair sorts before U+FB33, which code-point order would reverse)
		{`{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"},
		// the escapes: \b \f by name, other controls as \u00xx in lower case, U+2028, U+2029, <, >, & and U+007F as themselves
		{`["\b\f\u0001\u001f\u2028\u2029<>&` + "\u007f" + `"]`, "[\"\\b\\f\\u0001\\u001f\u2028\u2029<>&\u007f\"]"},
		{`[-0, 0.0, -0.0, 1.0, 100, 1e2, 9007199254740992, -9007199254740992]`, `[0,0,0,1,100,100,9007199254740992,-9007199254740992]`},
		{` { "a" : { } , "b" : [ ] } `, `{"a":{},"b":[]}`},
	} {
		got, err := CanonicalizeJSON([]byte(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", c.in, got, err, c.want)
		}
	}
	// refused: an integer literal no double holds exactly, a number beyond a double's range, text that is not one JSON value
	for _, in := range []string{`[9007199254740993]`, `{"a":-9007199254740993}`, `[18446744073709551615]`, `[1e400]`, `[-1e400]`, `{"a":1} {}`, `{"a":`, ``} {
		if got, err := CanonicalizeJSON([]byte(in)); err == nil {
			t.Errorf("%q has no canonical form, got %s", in, got)
		}
	}
	if _, err := CanonicalizeJSON([]byte(`[9007199254740993]`)); !errors.Is(err, ErrNotIJSON) || !strings.Contains(err.Error(), "9007199254740992") {
		t.Errorf("the refusal of an inexact integer names the class and the nearest double: %v", err)
	}
	// an integer literal above 2^53 is accepted only as the canonical spelling of its double: 2^60 written exactly is refused (it and its spelling would share a digest), its spelling is
	// accepted, and 2^53 itself (the largest magnitude every integer up to is exact) is accepted as written; a Go value goes through json.Marshal first
	if got, err := CanonicalJSON(map[string]any{"z": json.Number("1152921504606847000"), "a": "<"}); err != nil || string(got) != `{"a":"<","z":1152921504606847000}` {
		t.Errorf("a Go value: %s %v", got, err)
	}
	for _, refused := range []any{uint64(1) << 60, uint64(1)<<53 + 1, int64(math.MinInt64), json.Number("-1152921504606846976")} {
		if _, err := CanonicalJSON(map[string]any{"n": refused}); !errors.Is(err, ErrNotIJSON) {
			t.Errorf("the integer %v above 2^53 that is not its double's spelling is refused: %v", refused, err)
		}
	}
	for _, accepted := range []string{`[9007199254740992]`, `[-9007199254740992]`, `[-9223372036854776000]`, `[295147905179352830000]`} {
		if got, err := CanonicalizeJSON([]byte(accepted)); err != nil || string(got) != accepted {
			t.Errorf("%s is its own canonical form: %s %v", accepted, got, err)
		}
	}
	// I-JSON: an object with two members of one name is refused at any depth, by name
	for _, in := range []string{`{"a":1,"a":1}`, `[{"b":{"a":1,"a":2}}]`, `{"` + `\` + `u0061":1,"a":2}`} {
		if _, err := CanonicalizeJSON([]byte(in)); !errors.Is(err, ErrNotIJSON) || !strings.Contains(err.Error(), `two members named "a"`) {
			t.Errorf("%s holds a duplicate member: %v", in, err)
		}
	}
}

// TestEveryRefusalOfTheCanonicalFormIsNamed holds each refusal to its name (the names the shared vectors carry), and CanonicalNumber, which is exported and reads any text, to the JSON
// number grammar: a text strconv reads but JSON does not write is refused, never canonicalized.
func TestEveryRefusalOfTheCanonicalFormIsNamed(t *testing.T) {
	for in, want := range map[string]string{`{"a":1,"a":2}`: RefusalDuplicateMember, `[1e400]`: RefusalNumberRange, `[9007199254740993]`: RefusalInexactInteger,
		`{"a":1} {}`: RefusalNotJSON, `[01]`: RefusalNotJSON, ``: RefusalNotJSON} {
		if _, err := CanonicalizeJSON([]byte(in)); CanonicalRefusal(err) != want {
			t.Errorf("%q: refused as %q (%v), want %q", in, CanonicalRefusal(err), err, want)
		}
	}
	for _, text := range []string{"+1", "0x1p4", "01", "1.", ".5", "Infinity", "NaN", "1_000", " 1", "1e", "-"} {
		if got, err := CanonicalNumber(text); CanonicalRefusal(err) != RefusalNotJSON {
			t.Errorf("CanonicalNumber(%q) = %q (%v), want the refusal %q", text, got, err, RefusalNotJSON)
		}
	}
	if CanonicalRefusal(errors.New("another error")) != "" || CanonicalRefusal(nil) != "" {
		t.Error("an error that is no refusal of the form is named")
	}
}

// TestEveryCanonicalFormIsItsOwnCanonicalForm holds the form idempotent: the canonical output of every accepted input is accepted again and yields the same bytes.
func TestEveryCanonicalFormIsItsOwnCanonicalForm(t *testing.T) {
	inputs := []string{`{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001, 2.9514790517935283e20, 1e21, 5e-324, -1.7976931348623157e308, 1152921504606846976.0]}`,
		`{"€": 1, "😀": [true, null, {"דּ": " \b"}]}`, `[0.1, 100, 9007199254740992, -0, 1e-7, 123456789012345680000]`}
	for _, in := range inputs {
		once, err := CanonicalizeJSON([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		twice, err := CanonicalizeJSON(once)
		if err != nil || string(twice) != string(once) {
			t.Errorf("%s: the canonical form %s canonicalizes to %s (%v)", in, once, twice, err)
		}
	}
}
