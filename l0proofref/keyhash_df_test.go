// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/opendlt/infrix-verify/govproof"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DF-01 for govproof.KeyHash: the key hash a key page stores, computed by the verifier, equals Accumulate's protocol.PublicKeyHash for every type the
// verifier credits (ed25519, btc from a compressed or uncompressed key, eth from an uncompressed key), over 300 deterministic keys of each.
func TestDF01_KeyHashAgreesWithAccumulate(t *testing.T) {
	for i := 0; i < 300; i++ {
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], uint64(i))
		s := sha256.Sum256(append([]byte("keyhash-df"), seed[:]...))
		ek := ed25519.NewKeyFromSeed(s[:])
		sk := secp256k1.PrivKeyFromBytes(s[:])
		for _, c := range []struct {
			name string
			typ  protocol.SignatureType
			pub  []byte
		}{
			{"ed25519", protocol.SignatureTypeED25519, ek[32:]},
			{"btc", protocol.SignatureTypeBTC, sk.PubKey().SerializeCompressed()},
			{"eth", protocol.SignatureTypeETH, sk.PubKey().SerializeUncompressed()},
		} {
			want, err := protocol.PublicKeyHash(c.pub, c.typ)
			if err != nil {
				t.Fatal(err)
			}
			got, err := govproof.KeyHash(c.name, c.pub)
			if err != nil {
				t.Fatalf("%s %d: %v", c.name, i, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s key %d: govproof %x, Accumulate %x", c.name, i, got, want)
			}
		}
	}
	if _, err := govproof.KeyHash("rcd1", make([]byte, 32)); err == nil {
		t.Fatal("a type the verifier does not compute was given a key hash")
	}
}
