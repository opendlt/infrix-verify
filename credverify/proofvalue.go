// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"errors"
	"fmt"
	"strings"
)

// THE ENCODING THIS VERIFIER READS, AND WHY IT CHANGED.
//
// Until 2026-09-10 this package decoded proofValue with hex.DecodeString, and
// every Infrix producer emitted base64. The result was not a subtle
// incompatibility: the offline verifier could not verify a single credential
// the node issued, and every signature involved was perfectly valid. The
// register carried it as W.VC.PROOFVALUE.SINGLEENCODING, "highest severity",
// and it survived because each side was tested only against itself.
//
// The canonical encoding is multibase base58btc — a leading 'z' — which is what
// Ed25519Signature2020 and the Data Integrity suites specify. It is implemented
// here rather than imported because this module depends only on infrix-schema
// by design; TestCanonicalProofValueVectorMatchesTheHub pins it to the same
// fixed vector infrix-core asserts, so the two implementations cannot drift
// apart silently.

// proofValueMultibasePrefix is the multibase code for base58btc.
const proofValueMultibasePrefix = "z"

// base58btcAlphabet is the Bitcoin alphabet: no 0, O, I or l.
const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ErrProofValueEncoding marks a proofValue that is not multibase base58btc.
var ErrProofValueEncoding = errors.New("credverify: proofValue is not multibase base58btc")

// decodeProofValue parses a canonical proofValue into signature bytes.
//
// It REFUSES hex and base64 rather than falling back to them. A verifier that
// tries several encodings until one works cannot tell a stale producer from a
// forged credential, and reports neither.
func decodeProofValue(proofValue string) ([]byte, error) {
	trimmed := strings.TrimSpace(proofValue)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: value is empty", ErrProofValueEncoding)
	}
	if !strings.HasPrefix(trimmed, proofValueMultibasePrefix) {
		return nil, fmt.Errorf("%w: expected a leading %q, got %q — a producer older than "+
			"the single-encoding rule is still emitting hex or base64",
			ErrProofValueEncoding, proofValueMultibasePrefix, trimmed[:1])
	}
	data := trimmed[len(proofValueMultibasePrefix):]
	if data == "" {
		return nil, fmt.Errorf("%w: multibase prefix with no data", ErrProofValueEncoding)
	}
	decoded, ok := base58btcDecode(data)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not valid base58btc", ErrProofValueEncoding, data)
	}
	return decoded, nil
}

// encodeProofValue renders bytes as a canonical proofValue. It exists so the
// cross-module vector test can assert both directions against infrix-core.
func encodeProofValue(raw []byte) string {
	return proofValueMultibasePrefix + base58btcEncode(raw)
}

// base58btcDecode decodes big-endian base58. The second result is false for any
// character outside the alphabet.
func base58btcDecode(s string) ([]byte, bool) {
	out := []byte{0}
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(base58btcAlphabet, s[i])
		if idx < 0 {
			return nil, false
		}
		carry := idx
		for j := len(out) - 1; j >= 0; j-- {
			carry += 58 * int(out[j])
			out[j] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			out = append([]byte{byte(carry % 256)}, out...)
			carry /= 256
		}
	}
	// Each leading '1' is one leading zero byte. Strip the scratch leading zero
	// first, then restore exactly as many as the string declares.
	for len(out) > 1 && out[0] == 0 {
		out = out[1:]
	}
	if out[0] == 0 && len(out) == 1 {
		out = nil
	}
	leading := 0
	for leading < len(s) && s[leading] == base58btcAlphabet[0] {
		leading++
	}
	return append(make([]byte, leading), out...), true
}

// base58btcEncode encodes big-endian base58.
func base58btcEncode(raw []byte) string {
	leading := 0
	for leading < len(raw) && raw[leading] == 0 {
		leading++
	}
	var digits []byte
	for _, b := range raw {
		carry := int(b)
		for j := 0; j < len(digits); j++ {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	var sb strings.Builder
	for i := 0; i < leading; i++ {
		sb.WriteByte(base58btcAlphabet[0])
	}
	for i := len(digits) - 1; i >= 0; i-- {
		sb.WriteByte(base58btcAlphabet[digits[i]])
	}
	if sb.Len() == 0 {
		return ""
	}
	return sb.String()
}
