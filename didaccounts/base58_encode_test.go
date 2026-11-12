// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didaccounts

import (
	"math/big"
	"math/rand"
	"testing"
)

// referenceBase58 is the textbook division encoder, the spelling Base58Encode must keep byte for byte.
func referenceBase58(raw []byte) string {
	value := new(big.Int).SetBytes(raw)
	fiftyEight, mod := big.NewInt(58), new(big.Int)
	var digits []byte
	for value.Sign() > 0 {
		value.DivMod(value, fiftyEight, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}
	out := ""
	for _, b := range raw {
		if b != 0 {
			break
		}
		out += "1"
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out += string(digits[i])
	}
	return out
}

// TestBase58EncodeIsTheDivisionEncoderByteForByte (part 25f5): the encoder spells big.Int's base-58 text in the base58 alphabet; it must
// write exactly what the division encoder wrote, for the empty input, all-zero inputs, leading zeros and random bytes.
func TestBase58EncodeIsTheDivisionEncoderByteForByte(t *testing.T) {
	cases := [][]byte{{}, {0}, {0, 0, 0}, {0, 0, 1}, {57}, {58}, {255, 255}, {0, 255, 0}}
	r := rand.New(rand.NewSource(25))
	for i := 0; i < 2000; i++ {
		b := make([]byte, r.Intn(40))
		r.Read(b)
		if i%5 == 0 && len(b) > 2 {
			b[0], b[1] = 0, 0
		}
		cases = append(cases, b)
	}
	for _, c := range cases {
		if got, want := Base58Encode(c), referenceBase58(c); got != want {
			t.Fatalf("Base58Encode(%x) = %q, want %q", c, got, want)
		}
		if back := Base58Decode(Base58Encode(c)); string(back) != string(c) {
			t.Fatalf("decode(encode(%x)) = %x", c, back)
		}
	}
}
