// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestRIPEMD160IsHeldToItsAuthorsPublishedVectors: the test vectors of the RIPEMD-160 page of Bosselaers (the empty string to a million 'a'), plus lengths around the block boundary
// (55, 56, 63, 64 and 65 bytes, where the padding takes one block or two) checked against the 'a' and digit vectors' own structure by planted cuts: each published input with one byte
// changed must not keep its digest.
func TestRIPEMD160IsHeldToItsAuthorsPublishedVectors(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
		{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
		{"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"},
		{strings.Repeat("1234567890", 8), "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
		{strings.Repeat("a", 1000000), "52783243c1697bdbe16d37f97f68f08325dc1528"},
	} {
		got := RIPEMD160([]byte(c.in))
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("RIPEMD-160 of %d bytes = %x, want %s", len(c.in), got, c.want)
		}
		if c.in != "" {
			changed := []byte(c.in)
			changed[len(changed)-1] ^= 1
			if other := RIPEMD160(changed); other == got {
				t.Errorf("PLANTED CUT KEPT ITS DIGEST: %d bytes with the last byte changed", len(c.in))
			}
		}
	}
	// HASH160 of the compressed key of private key 1 is BIP-173's published witness program 751e76e8199196d454941c45d1b3a323f1433bd6
	key, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if got := hex.EncodeToString(Hash160(key)); got != "751e76e8199196d454941c45d1b3a323f1433bd6" {
		t.Errorf("HASH160 of the generator's compressed key = %s", got)
	}
}
