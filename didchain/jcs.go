// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// THE CANONICAL FORM (item 2c part 25g, row H3: the portable statement of the document hash, ledger raise L2557).
//
// Every JSON value a digest of this method covers (a DID document, an operation of a statement or of an update) is digested in ONE form a second implementation in any language
// reproduces from the JSON alone: the JSON Canonicalization Scheme, RFC 8785 (JCS). Before it, the document hash covered the bytes Go's encoder wrote for the document model (members in
// the struct's field order, `<`, `>` and `&` written as unicode escapes, the numbers of a free-form member as the encoder kept them): a verifier that is not this Go program could not
// reproduce them. The form is exactly RFC 8785:
//
//   - the value is I-JSON (RFC 7493): no object holds two members of one name (refused), every number is read as the nearest IEEE 754 double, as RFC 8785 reads it, and a number beyond
//     the range of a double is refused; an INTEGER literal (no fraction and no exponent) whose magnitude exceeds 2^53 is accepted only when it is written exactly as the canonical form
//     writes its double (1152921504606847000 for 2^60), and refused otherwise (9007199254740993, and 1152921504606846976 itself): the document model writes a Go integer as its exact
//     digits, so two documents that differ only in such an integer would otherwise share a digest, and the rule keeps every canonical output a canonical input of itself (an integer
//     the form writes in plain digits above 2^53 reads back to the same bytes); a string is valid Unicode (the encoder writes a byte that is not UTF-8 as U+FFFD);
//   - an object's members are sorted by their names compared as arrays of UTF-16 code units, an array keeps its order, there is no whitespace between tokens;
//   - a string is written with `"` and `\` escaped as `\"` and `\\`, the control characters U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`, `\f` and `\r`, every other
//     control character below U+0020 as `\u00` and two lower-case hexadecimal digits, and every other character (U+2028, U+2029, `<`, `>`, `&`, U+007F and every non-ASCII character
//     included) as itself in UTF-8;
//   - a number is written as ECMAScript's Number.prototype.toString writes the double (the shortest decimal that reads back as it, plain notation for an exponent from -7 to 20, the form
//     `d.ddde+N` / `de-N` outside it, negative zero as `0`); `true`, `false` and `null` as themselves.
//
// The vectors `canonical-json` of the shared vector set pin this form for every rule above (CanonicalJSONVectors), and both sibling implementations hold themselves to them.

// ErrNotIJSON is a value with no canonical form: an object with two members of one name, a number beyond the range of a double, or an integer literal above 2^53 that is not the
// canonical spelling of its double.
var ErrNotIJSON = errors.New("the value is not I-JSON (RFC 7493), so it has no canonical form (RFC 8785)")

// The refusals of the canonical form, each by name (CanonicalRefusal names them as the shared vectors do): the three kinds of ErrNotIJSON, and text that is not one JSON value.
var (
	ErrDuplicateMember = fmt.Errorf("%w: an object holds two members of one name", ErrNotIJSON)
	ErrNumberRange     = fmt.Errorf("%w: a number is beyond the range of a double", ErrNotIJSON)
	ErrInexactInteger  = fmt.Errorf("%w: an integer above 2^53 is not the canonical spelling of its double", ErrNotIJSON)
	ErrNotJSON         = errors.New("the text is not one JSON value")
)

// The names of the refusals in the shared vectors.
const (
	RefusalNotJSON         = "not-json"
	RefusalDuplicateMember = "duplicate-member"
	RefusalNumberRange     = "number-range"
	RefusalInexactInteger  = "inexact-integer"
)

// CanonicalRefusal names the refusal of the canonical form err is, or "" when it is none of them.
func CanonicalRefusal(err error) string {
	switch {
	case errors.Is(err, ErrDuplicateMember):
		return RefusalDuplicateMember
	case errors.Is(err, ErrNumberRange):
		return RefusalNumberRange
	case errors.Is(err, ErrInexactInteger):
		return RefusalInexactInteger
	case errors.Is(err, ErrNotJSON):
		return RefusalNotJSON
	}
	return ""
}

// CanonicalJSON is the RFC 8785 canonical form of a Go value: the value is marshalled, read back as generic JSON with every number kept as its text, and written in the canonical form.
// A value json.Marshal refuses, and a value that is not I-JSON (ErrNotIJSON), is an error.
func CanonicalJSON(v any) ([]byte, error) {
	first, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(first)
}

// CanonicalizeJSON is the RFC 8785 canonical form of JSON text. Text that is not one JSON value, or whose numbers are not I-JSON, is an error.
func CanonicalizeJSON(text []byte) ([]byte, error) {
	if !json.Valid(text) {
		// json.Valid refuses text that is not exactly one JSON value (trailing values and truncation included)
		return nil, ErrNotJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.UseNumber()
	generic, err := decodeIJSON(decoder)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// decodeIJSON reads one value of text json.Valid admitted, token by token, so that an object with two members of one name is refused (the generic decoder keeps the last silently).
func decodeIJSON(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		// the text was valid JSON, so the tokenizer cannot fail on it: a failure is a defect of this function, never of the input
		panic(fmt.Sprintf("statementchain: valid JSON did not tokenize: %v", err))
	}
	switch delim := token.(type) {
	case json.Delim:
		switch delim {
		case '[':
			items := []any{}
			for decoder.More() {
				item, err := decodeIJSON(decoder)
				if err != nil {
					return nil, err
				}
				items = append(items, item)
			}
			_, _ = decoder.Token() // the closing bracket of valid text
			return items, nil
		case '{':
			members := map[string]any{}
			for decoder.More() {
				nameToken, _ := decoder.Token() // a member name of valid text is a string
				name := nameToken.(string)
				if _, taken := members[name]; taken {
					return nil, fmt.Errorf("%w: the object holds two members named %q", ErrDuplicateMember, name)
				}
				value, err := decodeIJSON(decoder)
				if err != nil {
					return nil, err
				}
				members[name] = value
			}
			_, _ = decoder.Token() // the closing brace of valid text
			return members, nil
		}
		panic(fmt.Sprintf("statementchain: a value of valid JSON began with %q", delim))
	}
	return token, nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(value))
	case json.Number:
		text, err := CanonicalNumber(string(value))
		if err != nil {
			return err
		}
		out.WriteString(text)
	case string:
		writeCanonicalString(out, value)
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(value))
		for name := range value {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return lessUTF16(names[i], names[j]) })
		out.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, name)
			out.WriteByte(':')
			if err := writeCanonical(out, value[name]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		// the decoder above makes only the six kinds handled: anything else is a defect of this function, never of the input
		panic(fmt.Sprintf("statementchain: the canonical writer was handed a %T", v))
	}
	return nil
}

// lessUTF16 orders two names as RFC 8785 section 3.2.3 orders object members: by their UTF-16 code units.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeCanonicalString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	// ranging over a string yields U+FFFD for each byte that is not UTF-8, which is what json.Marshal writes for it
	for _, r := range s {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\f':
			out.WriteString(`\f`)
		case r == '\r':
			out.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

// jsonNumber is the number grammar of RFC 8259 section 6.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// maxExactInteger is 2^53: every integer of at most this magnitude is exactly a double, and its canonical spelling is its digits.
var maxExactInteger = new(big.Int).Lsh(big.NewInt(1), 53)

// CanonicalNumber writes a JSON number's text in the RFC 8785 form: the number is read as the nearest double, as the RFC reads it, and refused (ErrNotIJSON) when it is beyond the range
// of a double, or when it is an INTEGER LITERAL (no fraction, no exponent) of magnitude above 2^53 that is not written exactly as the form writes its double (jcs.go's rule above).
func CanonicalNumber(text string) (string, error) {
	if !jsonNumber.MatchString(text) {
		return "", fmt.Errorf("%w: %q is not a JSON number", ErrNotJSON, text)
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("%w: the number %s is beyond the range of a double", ErrNumberRange, text)
	}
	canonical := FormatECMAScriptNumber(f)
	if !strings.ContainsAny(text, ".eE") {
		// the text is a JSON integer literal (jsonNumber, no fraction and no exponent): decimal digits with an optional minus, which SetString always reads
		exact, _ := new(big.Int).SetString(text, 10)
		if new(big.Int).Abs(exact).Cmp(maxExactInteger) > 0 && text != canonical {
			return "", fmt.Errorf("%w: the integer %s is above 2^53 and is not the canonical spelling of its double (%s): two documents that differ in it would share a digest", ErrInexactInteger, text, canonical)
		}
	}
	return canonical, nil
}

// FormatECMAScriptNumber writes a finite double as ECMAScript's Number.prototype.toString does (ECMA-262, Number::toString with radix 10).
func FormatECMAScriptNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// the shortest digits that read back as f, and the exponent of the first: d.ddddde±XX
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponentText, _ := strings.Cut(e, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, _ := strconv.Atoi(exponentText)
	k, n := len(digits), exponent+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	exp := n - 1
	expSign := "+"
	if exp < 0 {
		expSign, exp = "-", -exp
	}
	if k == 1 {
		return sign + digits + "e" + expSign + strconv.Itoa(exp)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(exp)
}
