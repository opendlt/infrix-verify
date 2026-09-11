// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// THE CROSS-MODULE ANCHOR.
//
// This module cannot import infrix-core, and infrix-core's codec cannot import
// this one — that independence is deliberate, and it is also exactly how the
// two drifted to hex and base64 without either side's tests noticing. Both
// implementations round-tripped perfectly against themselves.
//
// So the two are pinned to a shared VALUE instead of to each other. These
// constants are duplicated verbatim in
// infrix-core/pkg/zkp/vc/proofvalue_test.go. If either module changes its
// encoding, the vector test in that module goes red and names this one.
const (
	// 64 bytes, 0x00..0x3f — the size and shape of an Ed25519 signature.
	canonicalVectorHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	canonicalVectorString = "z1GMkH3brNXiNNs1tiFZHu4yZSRrzJwxi5wB9bHFtMinfCXNnR1adh8Vo8NTheK4evneedH4qmvjeqcBBNAefgS"
)

func canonicalVectorBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(canonicalVectorHex)
	if err != nil {
		t.Fatalf("decode the vector: %v", err)
	}
	return b
}

// TestCanonicalProofValueVectorMatchesTheHub is the fence against drift.
func TestCanonicalProofValueVectorMatchesTheHub(t *testing.T) {
	raw := canonicalVectorBytes(t)

	if got := encodeProofValue(raw); got != canonicalVectorString {
		t.Fatalf("this module encodes the shared vector differently from infrix-core.\n"+
			" got: %s\nwant: %s\n\nThe two implementations have drifted, which is the exact "+
			"failure that left the offline verifier unable to read a single credential the "+
			"node issued.", got, canonicalVectorString)
	}

	back, err := decodeProofValue(canonicalVectorString)
	if err != nil {
		t.Fatalf("this module cannot decode the shared vector: %v", err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatalf("decoding the shared vector produced different bytes:\n got %x\nwant %x", back, raw)
	}
}

func TestProofValueRoundTrips(t *testing.T) {
	for _, in := range [][]byte{
		{0x00},
		{0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0x00}, 8), // leading zeros: the classic base58 bug
		{0x00, 0x00, 0x01, 0x02},
		canonicalVectorBytes(t),
		bytes.Repeat([]byte{0xAB}, 192),
	} {
		out, err := decodeProofValue(encodeProofValue(in))
		if err != nil {
			t.Fatalf("round-trip %x: %v", in, err)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("round-trip changed the bytes: %x -> %x", in, out)
		}
	}
}

// TestDecodeRefusesTheEncodingThisVerifierUsedToUse is the regression.
//
// hex is not merely "another encoding" here — it is what THIS FILE's package
// decoded for its entire life, against producers that never emitted it.
func TestDecodeRefusesTheEncodingThisVerifierUsedToUse(t *testing.T) {
	raw := canonicalVectorBytes(t)
	for _, tc := range []struct{ name, value string }{
		{"hex — what this verifier used to decode", hex.EncodeToString(raw)},
		{"standard base64 — what the BBS producers used to emit", base64.StdEncoding.EncodeToString(raw)},
		{"raw base64url — what the Ed25519 issuer used to emit", base64.RawURLEncoding.EncodeToString(raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeProofValue(tc.value); err == nil {
				t.Fatalf("%s was accepted. Falling back through the old encodings would make "+
					"every producer look correct and hide the stale one.", tc.name)
			} else if !errors.Is(err, ErrProofValueEncoding) {
				t.Errorf("error does not wrap ErrProofValueEncoding: %v", err)
			}
		})
	}
}

func TestDecodeRefusesMalformedValues(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty", ""},
		{"prefix only", "z"},
		{"wrong multibase base", "uAAAA"},
		{"outside the base58 alphabet", "z0OIl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeProofValue(tc.value); err == nil {
				t.Fatalf("%q was accepted", tc.value)
			}
		})
	}
}

// TestNoHexDecodeRemainsOnAProofValue keeps the old call from coming back.
func TestNoHexDecodeRemainsOnAProofValue(t *testing.T) {
	src, err := readSource("credverify.go")
	if err != nil {
		t.Fatalf("read credverify.go: %v", err)
	}
	for _, banned := range []string{
		"hex.DecodeString(vc.Proof.ProofValue)",
		"hex.DecodeString(vp.Proof.ProofValue)",
		"base64.StdEncoding.DecodeString(vc.Proof.ProofValue)",
		"base64.RawURLEncoding.DecodeString(vc.Proof.ProofValue)",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("credverify.go still contains %q — proofValue has one decoder, "+
				"decodeProofValue", banned)
		}
	}
	if !strings.Contains(src, "decodeProofValue(vc.Proof.ProofValue)") {
		t.Error("the issuer signature path no longer calls decodeProofValue")
	}
	if !strings.Contains(src, "decodeProofValue(vp.Proof.ProofValue)") {
		t.Error("the holder signature path no longer calls decodeProofValue")
	}
}

// readSource returns a file from this package's directory.
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
