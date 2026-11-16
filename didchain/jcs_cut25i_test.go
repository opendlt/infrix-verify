// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Part 25i, cut of jcs.go: the canonical form's refusals, its defects' panics, the UTF-16 member order and the ECMAScript number spelling, each at its boundary.

func wantPanic(t *testing.T, name, words string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), words) {
			t.Errorf("%s: want a panic saying %q, got %v", name, words, r)
		}
	}()
	f()
}

func TestAValueJSONRefusesIsRefusedWithJSONsOwnError(t *testing.T) {
	_, err := CanonicalJSON(make(chan int))
	var unsupported *json.UnsupportedTypeError
	if !errors.As(err, &unsupported) || errors.Is(err, ErrNotJSON) {
		t.Fatalf("want json's unsupported-type error, got %v", err)
	}
}

func TestTheCanonicalWritersDefectsPanicWithTheirReasons(t *testing.T) {
	wantPanic(t, "text that does not tokenize", "valid JSON did not tokenize", func() {
		_, _ = decodeIJSON(json.NewDecoder(strings.NewReader("}")))
	})
	wantPanic(t, "a value that begins with a closing bracket", "a value of valid JSON began with", func() {
		decoder := json.NewDecoder(strings.NewReader("[]"))
		_, _ = decoder.Token()
		_, _ = decodeIJSON(decoder)
	})
	wantPanic(t, "a kind the decoder never makes", "the canonical writer was handed a float64", func() {
		_ = writeCanonical(&bytes.Buffer{}, 1.5)
	})
}

func TestMembersAreOrderedByTheirUTF16CodeUnits(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"a", "b", true}, {"b", "a", false}, {"aa", "ab", true}, {"ab", "aa", false}, {"a", "ab", true}, {"ab", "a", false}, {"a", "a", false}, {"", "a", true},
		// U+1F600 is the surrogate pair D83D DE00, below U+FFFF in UTF-16 though above it as a code point
		{"\U0001F600", "￿", true}, {"￿", "\U0001F600", false},
	} {
		if got := lessUTF16(c.a, c.b); got != c.less {
			t.Errorf("lessUTF16(%q, %q) = %t, want %t", c.a, c.b, got, c.less)
		}
	}
}

func TestATabIsEscapedInTheCanonicalForm(t *testing.T) {
	out, err := CanonicalizeJSON([]byte(`"a\tb"`))
	if err != nil || string(out) != `"a\tb"` {
		t.Fatalf("%s %v", out, err)
	}
}

func TestNumbersAreSpelledAsECMAScriptSpellsThemAtEveryBoundaryOfItsForms(t *testing.T) {
	for in, want := range map[float64]string{
		1:          "1",
		-1:         "-1",
		123:        "123",
		1.5:        "1.5",
		-1.5:       "-1.5",
		0.5:        "0.5",
		1e20:       "100000000000000000000",
		1.5e20:     "150000000000000000000",
		1e21:       "1e+21",
		1.5e21:     "1.5e+21",
		0.000001:   "0.000001",
		0.0000015:  "0.0000015",
		1e-7:       "1e-7",
		-1.5e-7:    "-1.5e-7",
		123.456:    "123.456",
		1e300:      "1e+300",
		5e-324:     "5e-324",
		4294967295: "4294967295",
	} {
		if got := FormatECMAScriptNumber(in); got != want {
			t.Errorf("FormatECMAScriptNumber(%v) = %s, want %s", in, got, want)
		}
	}
	for text, want := range map[string]string{"-0": "0", "9007199254740992": "9007199254740992", "-9007199254740992": "-9007199254740992", "1.50": "1.5", "1E2": "100"} {
		if got, err := CanonicalNumber(text); err != nil || got != want {
			t.Errorf("CanonicalNumber(%s) = %s %v, want %s", text, got, err, want)
		}
	}
	for _, text := range []string{"9007199254740993", "-9007199254740993", "100000000000000000000000"} {
		if _, err := CanonicalNumber(text); !errors.Is(err, ErrInexactInteger) {
			t.Errorf("CanonicalNumber(%s): %v, want ErrInexactInteger", text, err)
		}
	}
	if _, err := CanonicalNumber("1e400"); !errors.Is(err, ErrNumberRange) {
		t.Errorf("a number beyond a double: %v", err)
	}
}
