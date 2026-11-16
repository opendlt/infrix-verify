// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustChainDID(t *testing.T, did string) ChainAccount {
	t.Helper()
	a, err := ParseChainDID(did)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func refusedAs(t *testing.T, err error, words string) {
	t.Helper()
	if !errors.Is(err, ErrChainSignature) || !strings.Contains(err.Error(), words) {
		t.Errorf("want a refusal naming %q, got %v", words, err)
	}
}

// TestTheVerifierRegistryIsTheNamespaceList: exactly one verifier per namespace of the account standard, each of its own scheme.
func TestTheVerifierRegistryIsTheNamespaceList(t *testing.T) {
	if got, want := ChainVerifierNamespaces(), didaccounts.Namespaces(); !reflect.DeepEqual(got, want) {
		t.Fatalf("verifiers %v, namespaces %v", got, want)
	}
	for ns, scheme := range map[string]string{"eip155": ChainSchemeEIP155, "solana": ChainSchemeSolana, "bip122": ChainSchemeBIP122, "cosmos": ChainSchemeCosmos} {
		if v, ok := ChainVerifier(ns); !ok || v.Scheme() != scheme {
			t.Errorf("%s: %v", ns, v)
		}
	}
	if got := string(ChainStatementMessage([32]byte{1})); len(got) != 88 || got != ChainStatementMessagePrefix+"01"+strings.Repeat("0", 62) {
		t.Errorf("statement message %q", got)
	}
}

// TestTheSecp256k1ArithmeticIsTheCurves: G is on the curve, n*G is the point at infinity, 2*G is SEC 2's published double, a key round-trips both SEC 1 forms, and every malformed key
// is refused.
func TestTheSecp256k1ArithmeticIsTheCurves(t *testing.T) {
	if !secpOnCurve(secpGx, secpGy) || !secpMul(secpG, secpN).inf {
		t.Fatal("G is not a point of order n")
	}
	two := secpMul(secpG, big.NewInt(2))
	if hex.EncodeToString(two.serializeCompressed()) != "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" {
		t.Errorf("2G = %x", two.serializeCompressed())
	}
	if sum := secpAdd(secpG, secpG); sum.x.Cmp(two.x) != 0 || secpAdd(two, secpPoint{inf: true}).x.Cmp(two.x) != 0 {
		t.Error("doubling and adding infinity disagree")
	}
	negG := secpPoint{x: secpGx, y: new(big.Int).Sub(secpP, secpGy)}
	if !secpAdd(secpG, negG).inf {
		t.Error("G + (-G) is not infinity")
	}
	for _, form := range [][]byte{secpG.serializeCompressed(), secpG.serializeUncompressed(), two.serializeCompressed()} {
		p, err := ParseSecp256k1PublicKey(form)
		if err != nil || p.x.Cmp(new(big.Int).SetBytes(form[1:33])) != 0 {
			t.Errorf("%x: %v", form, err)
		}
	}
	bad := secpG.serializeUncompressed()
	bad[64] ^= 1
	for _, key := range [][]byte{nil, bad, append([]byte{5}, secpG.serializeCompressed()[1:]...), append([]byte{2}, make([]byte, 32)...), append([]byte{2}, secpP.Bytes()...)} {
		if _, err := ParseSecp256k1PublicKey(key); !errors.Is(err, ErrSecp256k1) {
			t.Errorf("%x was read as a key: %v", key, err)
		}
	}
	// scalars: zero, at or above n, and high s are refused; a recovery id above 3 and a short hash too
	nBytes := secpN.FillBytes(make([]byte, 32))
	one := append(make([]byte, 31), 1)
	high := new(big.Int).Add(secpHalfN, big.NewInt(1)).FillBytes(make([]byte, 32))
	for _, rs := range [][]byte{append(make([]byte, 32), one...), append(append([]byte(nil), nBytes...), one...), append(append([]byte(nil), one...), nBytes...), append(append([]byte(nil), one...), high...), one} {
		if _, err := RecoverSecp256k1(rs, 0, make([]byte, 32)); !errors.Is(err, ErrSecp256k1) {
			t.Errorf("r||s %x recovered: %v", rs, err)
		}
	}
	if _, err := RecoverSecp256k1(append(append([]byte(nil), one...), one...), 4, make([]byte, 32)); !errors.Is(err, ErrSecp256k1) {
		t.Error("recovery id 4")
	}
	if _, err := RecoverSecp256k1(append(append([]byte(nil), one...), one...), 0, make([]byte, 31)); !errors.Is(err, ErrSecp256k1) {
		t.Error("a 31-byte hash")
	}
	if VerifySecp256k1(secpG, make([]byte, 31), append(append([]byte(nil), one...), one...)) || VerifySecp256k1(secpPoint{inf: true}, make([]byte, 32), append(append([]byte(nil), one...), one...)) {
		t.Error("a short hash or the point at infinity verified")
	}
}

// TestTheEIP155VerifierHoldsThePublishedPersonalSignVector: web3.js's documented eth.accounts.sign("Some data", 0x4c08...) and its cuts.
func TestTheEIP155VerifierHoldsThePublishedPersonalSignVector(t *testing.T) {
	message := []byte("Some data")
	if got := hex.EncodeToString(EIP191PersonalMessageHash(message)); got != "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655" {
		t.Fatalf("EIP-191 hash %s", got)
	}
	signature := mustHex(t, "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c")
	key, err := RecoverSecp256k1(signature[:64], signature[64]-27, EIP191PersonalMessageHash(message))
	if err != nil {
		t.Fatal(err)
	}
	signer := key.serializeUncompressed()
	account := mustChainDID(t, "did:infrix:v1:chain:eip155:1:0x2c7536e3605d9c16a7a3d7b1898e529396a65c23")
	v := eip155Verifier{}
	if err := v.Verify(account, message, signer, signature); err != nil {
		t.Fatalf("the published vector is refused: %v", err)
	}
	low := append([]byte(nil), signature...)
	low[64] = 1
	if err := v.Verify(account, message, signer, low); err != nil {
		t.Errorf("v=1: %v", err)
	}
	if err := v.Verify(account, []byte("Some datb"), signer, signature); err == nil {
		t.Error("a signature over another message verified")
	}
	refusedAs(t, v.Verify(mustChainDID(t, "did:infrix:v1:chain:eip155:1:0x0000000000000000000000000000000000000001"), message, signer, signature), "the DID names 0x0000000000000000000000000000000000000001")
	refusedAs(t, v.Verify(account, message, key.serializeCompressed(), signature), "the signer is not the public key")
	bad := append([]byte(nil), signature...)
	bad[64] = 29
	refusedAs(t, v.Verify(account, message, signer, bad), "v is 29")
	refusedAs(t, v.Verify(account, message, signer, signature[:64]), "65 bytes")
	s := new(big.Int).Sub(secpN, new(big.Int).SetBytes(signature[32:64])).FillBytes(make([]byte, 32))
	refusedAs(t, v.Verify(account, message, signer, append(append(append([]byte(nil), signature[:32]...), s...), signature[64])), "upper half")
}

// TestTheSolanaVerifierHoldsTheRFC8032Vectors: RFC 8032 section 7.1 tests 1 to 3, the account being the base58 of the public key.
func TestTheSolanaVerifierHoldsTheRFC8032Vectors(t *testing.T) {
	v := solanaVerifier{}
	for _, c := range []struct{ pub, msg, sig string }{
		{"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
		{"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	} {
		pub, msg, sig := mustHex(t, c.pub), mustHex(t, c.msg), mustHex(t, c.sig)
		account := mustChainDID(t, "did:infrix:v1:chain:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:"+didaccounts.Base58Encode(pub))
		if err := v.Verify(account, msg, pub, sig); err != nil {
			t.Errorf("RFC 8032 vector %s: %v", c.pub[:8], err)
		}
		tampered := append([]byte(nil), sig...)
		tampered[0] ^= 1
		refusedAs(t, v.Verify(account, msg, pub, tampered), "does not verify")
		refusedAs(t, v.Verify(account, msg, pub, sig[:63]), "64 bytes")
		refusedAs(t, v.Verify(account, msg, pub[1:], sig), "is not the account's public key")
	}
}

// TestTheBIP122VerifierHoldsThePublishedMessageSignature: the bitcoinjs-message README example (a mainnet P2PKH address of a compressed key), its P2WPKH form, and every header and
// address kind this method refuses.
func TestTheBIP122VerifierHoldsThePublishedMessageSignature(t *testing.T) {
	v := bip122Verifier{}
	message := []byte("This is an example of a signed message.")
	signature, _ := base64.StdEncoding.DecodeString("H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk=")
	key, err := RecoverSecp256k1(signature[1:], (signature[0]-27)%4, BitcoinMessageHash(message))
	if err != nil {
		t.Fatal(err)
	}
	signer := key.serializeCompressed()
	const btc = "did:infrix:v1:chain:bip122:000000000019d6689c085ae165831e93:"
	account := mustChainDID(t, btc+"1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV")
	if err := v.Verify(account, message, signer, signature); err != nil {
		t.Fatalf("the published vector: %v", err)
	}
	if err := v.Verify(account, append(message, '.'), signer, signature); err == nil {
		t.Error("a signature over another message verified")
	}
	refusedAs(t, v.Verify(account, message, key.serializeUncompressed(), signature), "the signer is not the public key")
	segwit := append([]byte{39 + (signature[0]-27)%4}, signature[1:]...)
	program, _ := didaccounts.ConvertBits(Hash160(signer), 8, 5, true)
	address, err := didaccounts.Bech32Encode("bc", append([]byte{0}, program...), didaccounts.Bech32)
	if err != nil {
		t.Fatal(err)
	}
	p2wpkh := mustChainDID(t, btc+address)
	if err := v.Verify(p2wpkh, message, signer, segwit); err != nil {
		t.Errorf("the P2WPKH form: %v", err)
	}
	refusedAs(t, v.Verify(p2wpkh, message, signer, signature), "is p2wpkh")
	refusedAs(t, v.Verify(account, message, signer, segwit), "names a p2wpkh signature")
	refusedAs(t, v.Verify(account, message, signer, append([]byte{35}, signature[1:]...)), "P2SH-P2WPKH")
	for _, h := range []byte{26, 43, 0, 255} {
		refusedAs(t, v.Verify(account, message, signer, append([]byte{h}, signature[1:]...)), "not a BIP-137 header")
	}
	refusedAs(t, v.Verify(account, message, signer, signature[:64]), "65 bytes")
	refusedAs(t, v.Verify(mustChainDID(t, btc+"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), message, signer, signature), "P2SH account")
	refusedAs(t, v.Verify(mustChainDID(t, btc+"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), message, signer, signature), "p2wsh account")
	refusedAs(t, v.Verify(mustChainDID(t, btc+"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"), message, signer, signature), "p2tr account")
	// a long message takes the three-byte CompactSize
	if len(BitcoinMessageHash(make([]byte, 300))) != 32 || len(BitcoinMessageHash(make([]byte, 70000))) != 32 {
		t.Error("CompactSize of a long message")
	}
}

// TestTheCosmosVerifierSignsTheADR036Document: the sign document is ADR-036's, byte for byte, and the refusals by name (the valid signature is the shared vector's).
func TestTheCosmosVerifierSignsTheADR036Document(t *testing.T) {
	address := "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"
	program, _ := didaccounts.ConvertBits(Hash160(secpG.serializeCompressed()), 8, 5, true)
	if got, _ := didaccounts.Bech32Encode("cosmos", program, didaccounts.Bech32); got != address {
		t.Fatalf("the cosmos address of private key 1 is %s", got)
	}
	want := `{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"aGVsbG8=","signer":"` + address + `"}}],"sequence":"0"}`
	if got := string(CosmosADR036SignDoc([]byte("hello"), address)); got != want {
		t.Fatalf("sign doc %s", got)
	}
	v := cosmosVerifier{}
	account := mustChainDID(t, "did:infrix:v1:chain:cosmos:cosmoshub-4:"+address)
	two := secpMul(secpG, big.NewInt(2))
	refusedAs(t, v.Verify(account, nil, two.serializeCompressed(), make([]byte, 64)), "the signer's address")
	refusedAs(t, v.Verify(account, nil, secpG.serializeUncompressed(), make([]byte, 64)), "33-byte")
	refusedAs(t, v.Verify(account, nil, append([]byte{5}, secpG.serializeCompressed()[1:]...), make([]byte, 64)), "not a secp256k1 public key")
	refusedAs(t, v.Verify(account, nil, secpG.serializeCompressed(), make([]byte, 64)), "does not verify")
	module, _ := didaccounts.Bech32Encode("cosmos", mustConvert(t, make([]byte, 32)), didaccounts.Bech32)
	refusedAs(t, v.Verify(mustChainDID(t, "did:infrix:v1:chain:cosmos:cosmoshub-4:"+module), nil, secpG.serializeCompressed(), make([]byte, 64)), "20-byte account address")
}

func mustConvert(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := didaccounts.ConvertBits(b, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAChainDIDIsReadOnlyInItsCanonicalSpelling: the grammar, the account standard and the one spelling.
func TestAChainDIDIsReadOnlyInItsCanonicalSpelling(t *testing.T) {
	for _, did := range []string{"did:infrix:v1:chain:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "did:infrix:v1:chain:eip155:1", "did:infrix:v1:anon:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
		"did:infrix:v1:chain:tezos:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"} {
		if _, err := ParseChainDID(did); !errors.Is(err, ErrNotChainDID) {
			t.Errorf("%s: %v", did, err)
		}
	}
	if a, err := ParseChainDID("did:infrix:v1:chain:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"); err != nil || a.Namespace != "eip155" || a.Reference != "1" {
		t.Errorf("%+v %v", a, err)
	}
	if (ChainAuthorizer{}).Scheme(&Entry{DID: "did:x"}) != "" {
		t.Error("a DID that is not a chain DID has a scheme")
	}
	if err := (ChainAuthorizer{}).Authorize(nil, &Entry{DID: "did:x"}, [32]byte{}); !errors.Is(err, ErrNotChainDID) {
		t.Errorf("authorize a DID that is not a chain DID: %v", err)
	}
}
