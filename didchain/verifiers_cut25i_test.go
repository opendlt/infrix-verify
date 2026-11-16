// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// Part 25i, the cut of didchain/secp256k1.go and verifiers.go: the scalars, the recovery ids, the point at infinity, the reduced coordinates, CompactSize, the BIP-137 headers
// and each verifier's refusal of an account, each held exactly.

func cut32(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }

func TestTheSecp256k1ScalarsAndRecoveryAreHeldAtTheirEdges(t *testing.T) {
	one := big.NewInt(1)
	rs := func(r, s *big.Int) []byte { return append(cut32(r), cut32(s)...) }
	for name, c := range map[string]struct {
		rs    []byte
		words string
	}{
		"63 bytes":     {make([]byte, 63), "not 64 bytes"},
		"s zero":       {rs(one, big.NewInt(0)), "s is zero or not below the order"},
		"s the order":  {rs(one, secpN), "s is zero or not below the order"},
		"s above half": {rs(one, new(big.Int).Add(secpHalfN, one)), "upper half"},
	} {
		if _, _, err := secpScalars(c.rs); err == nil || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want %q, got %v", name, c.words, err)
		}
	}
	if _, _, err := secpScalars(rs(one, secpHalfN)); err != nil {
		t.Errorf("s at half the order: %v", err)
	}
	// the published personal_sign vector (id 1): ids 0 to 3 pass the id check, 4 does not; ids 2 and 3 name x = r + n, which no point has
	signature := mustHex(t, "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c")
	hash := EIP191PersonalMessageHash([]byte("Some data"))
	if _, err := RecoverSecp256k1(signature[:64], 1, hash); err != nil {
		t.Fatalf("the published vector: %v", err)
	}
	for _, id := range []byte{2, 3} {
		if _, err := RecoverSecp256k1(signature[:64], id, hash); err == nil || !strings.Contains(err.Error(), "no curve point has the x") {
			t.Errorf("recovery id %d: %v", id, err)
		}
	}
	if _, err := RecoverSecp256k1(signature[:64], 4, hash); err == nil || !strings.Contains(err.Error(), "the recovery id is not 0 to 3") {
		t.Errorf("recovery id 4: %v", err)
	}
	if _, err := RecoverSecp256k1(signature[:64], 3, hash[:31]); err == nil || !strings.Contains(err.Error(), "the hash is not 32 bytes") {
		t.Errorf("a 31-byte hash: %v", err)
	}
	// R = G and e = s: the key r^-1 (sG - eG) is the point at infinity, which is no key
	if _, err := RecoverSecp256k1(rs(new(big.Int).Mod(secpG.x, secpN), one), 0, cut32(one)); err == nil || !strings.Contains(err.Error(), "the signature recovers no key that verifies it") {
		t.Errorf("a signature that recovers the point at infinity: %v", err)
	}
}

func TestACoordinateThatIsNotReducedNamesNoPoint(t *testing.T) {
	if !secpOnCurve(secpG.x, secpG.y) {
		t.Fatal("G is not on the curve")
	}
	beyond := func(v *big.Int) *big.Int { return new(big.Int).Add(v, secpP) }
	for name, xy := range map[string][2]*big.Int{
		"x plus p":  {beyond(secpG.x), secpG.y},
		"y plus p":  {secpG.x, beyond(secpG.y)},
		"x below 0": {new(big.Int).Sub(secpG.x, secpP), secpG.y},
		"y below 0": {secpG.x, new(big.Int).Sub(secpG.y, secpP)},
	} {
		if secpOnCurve(xy[0], xy[1]) {
			t.Errorf("%s is on the curve", name)
		}
	}
	if _, ok := secpLift(beyond(secpG.x), false); ok {
		t.Error("an x past p lifts")
	}
	if p, ok := secpLift(secpG.x, false); !ok || p.y.Cmp(secpG.y) != 0 {
		t.Errorf("G's x lifts to %v %v", p, ok)
	}
	if sum := secpAdd(secpG, secpPoint{x: secpG.x, y: new(big.Int).Sub(secpP, secpG.y)}); !sum.inf {
		t.Error("G + -G is not the point at infinity")
	}
}

func TestTheChainVerifiersRefuseEachAccountByItsOwnWords(t *testing.T) {
	for _, c := range []struct {
		n    uint64
		want string
	}{
		{0xfc, "fc"}, {0xfd, "fdfd00"}, {0xffff, "fdffff"}, {0x10000, "fe00000100"}, {0xffffffff, "feffffffff"}, {0x100000000, "ff0000000001000000"},
	} {
		var buf bytes.Buffer
		writeCompactSize(&buf, c.n)
		if got := hex.EncodeToString(buf.Bytes()); got != c.want {
			t.Errorf("CompactSize(%#x) = %s, want %s", c.n, got, c.want)
		}
	}
	if got := hex.EncodeToString(base32Groups([]byte{1, 2})); got != "00040100" {
		t.Errorf("base32Groups: %s", got)
	}
	if _, err := ParseChainDID("did:infrix:v1:chain:eip155:1:0x12"); err == nil || strings.Contains(err.Error(), "canonical spelling") {
		t.Errorf("an account its standard refuses: %v", err)
	}
	refusedAs(t, solanaVerifier{}.Verify(ChainAccount{Namespace: "solana", Account: "abc"}, []byte("m"), didaccounts.Base58Decode("abc"), make([]byte, 64)), "is not a 32-byte public key")
	refusedAs(t, bip122Verifier{}.Verify(ChainAccount{Namespace: "bip122", Reference: "000000000019d6689c085ae165831e93", Account: "1NotAnAddress"}, []byte("m"), nil, make([]byte, 65)), "is not a Bitcoin address of its network")
	address, err := didaccounts.Bech32Encode("cosmos", make([]byte, 31), didaccounts.Bech32)
	if err != nil {
		t.Fatal(err)
	}
	refusedAs(t, cosmosVerifier{}.Verify(ChainAccount{Namespace: "cosmos", Reference: "cosmoshub-4", Account: address}, []byte("m"), make([]byte, 33), make([]byte, 64)), "is not a 20-byte account address")
	refusedAs(t, cosmosVerifier{}.Verify(ChainAccount{Namespace: "cosmos", Reference: "cosmoshub-4", Account: "cosmos1notbech32"}, []byte("m"), make([]byte, 33), make([]byte, 64)), "is not bech32")
	p2pkh := ChainAccount{Namespace: "bip122", Reference: "000000000019d6689c085ae165831e93", Account: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}
	signer := cut32(big.NewInt(5))
	signer = append([]byte{2}, signer...)
	for header := 0; header < 256; header++ {
		err := bip122Verifier{}.Verify(p2pkh, []byte("m"), signer, append([]byte{byte(header)}, bytes.Repeat([]byte{1}, 64)...))
		switch {
		case header >= 27 && header <= 34, header >= 39 && header <= 42:
			if err == nil || strings.Contains(err.Error(), "not a BIP-137 header") || strings.Contains(err.Error(), "P2SH-P2WPKH") {
				t.Errorf("header %d: %v", header, err)
			}
		case header >= 35 && header <= 38:
			if err == nil || !strings.Contains(err.Error(), "P2SH-P2WPKH") {
				t.Errorf("header %d: %v", header, err)
			}
		default:
			if err == nil || !strings.Contains(err.Error(), "not a BIP-137 header") {
				t.Errorf("header %d: %v", header, err)
			}
		}
	}
}
