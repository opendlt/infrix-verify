// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didaccounts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// THE SHARED did:infrix VECTOR SET, ACCOUNT STANDARDS (infrix core part 25f2, row D2). The vector file is the one credverify pins (credverify/testdata/did-vectors-v1.json, the exact output of
// `infrix did vectors --out` in infrix core); this package is held to its `bech32` and `chainAccounts` sections, to its `parse` and `construct` vectors of the chain profile, and to the
// standards' own published examples.

const pinnedDIDVectorsSHA256 = "78f95ed25bdb9164fceea9360065b3d7adf638c0ab454ee5fba824d87df5d9e3"

type vectorSet struct {
	Spec      string `json:"spec"`
	NetworkID string `json:"networkId"`
	Parse     []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Valid     bool   `json:"valid"`
		Canonical string `json:"canonical"`
		Refusal   string `json:"refusal"`
	} `json:"parse"`
	Construct []struct {
		Name      string   `json:"name"`
		Profile   string   `json:"profile"`
		Args      []string `json:"args"`
		Canonical string   `json:"canonical"`
	} `json:"construct"`
	Bech32 []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Valid     bool   `json:"valid"`
		Hrp       string `json:"hrp"`
		Variant   string `json:"variant"`
		MaxLength int    `json:"maxLength"`
	} `json:"bech32"`
	ChainAccounts []struct {
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		Reference  string `json:"reference"`
		Account    string `json:"account"`
		Valid      bool   `json:"valid"`
		Canonical  string `json:"canonical"`
		Kind       string `json:"kind"`
		PayloadHex string `json:"payloadHex"`
	} `json:"chainAccounts"`
}

func loadVectors(t *testing.T) vectorSet {
	t.Helper()
	raw, err := os.ReadFile("../credverify/testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pinnedDIDVectorsSHA256 {
		t.Fatalf("did vectors sha256 = %s, pinned %s: re-export with `infrix did vectors --out` and update every repository together", got, pinnedDIDVectorsSHA256)
	}
	var set vectorSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if set.Spec != "did-infrix-v1" || len(set.Bech32) < 24 || len(set.ChainAccounts) < 40 {
		t.Fatalf("vector set shape changed: spec %q, %d bech32, %d chain accounts", set.Spec, len(set.Bech32), len(set.ChainAccounts))
	}
	return set
}

func TestEveryBech32VectorDecodesOrIsRefusedAsBIP173AndBIP350Say(t *testing.T) {
	for _, v := range loadVectors(t).Bech32 {
		hrp, data, variant, err := Bech32Decode(v.Input, v.MaxLength)
		if !v.Valid {
			if err == nil {
				t.Errorf("%s: %q was accepted", v.Name, v.Input)
			} else if !errors.Is(err, ErrInvalidAccount) {
				t.Errorf("%s: the refusal does not wrap ErrInvalidAccount: %v", v.Name, err)
			}
			continue
		}
		want := map[string]Variant{"bech32": Bech32, "bech32m": Bech32m}[v.Variant]
		if err != nil || hrp != v.Hrp || variant != want {
			t.Errorf("%s: %q decodes to %q %v (%v), want %q %s", v.Name, v.Input, hrp, variant, err, v.Hrp, v.Variant)
			continue
		}
		// the encoder is the decoder's inverse, in the variant the string carries
		if again, err := Bech32Encode(hrp, data, variant); err != nil || again != strings.ToLower(v.Input) {
			t.Errorf("%s: re-encoded %q (%v), want %q", v.Name, again, err, strings.ToLower(v.Input))
		}
	}
}

func TestEveryChainAccountVectorIsReadByTheStandardOfItsChain(t *testing.T) {
	valid, refused := map[string]int{}, map[string]int{}
	for _, v := range loadVectors(t).ChainAccounts {
		got, err := NormalizeChainAccount(v.Namespace, v.Reference, v.Account)
		if !v.Valid {
			if !errors.Is(err, ErrInvalidAccount) {
				t.Errorf("%s: %q: err = %v, want ErrInvalidAccount", v.Name, v.Account, err)
			}
			refused[v.Namespace]++
			continue
		}
		if err != nil || got != v.Canonical {
			t.Errorf("%s: %q normalizes to %q (%v), want %q", v.Name, v.Account, got, err, v.Canonical)
		}
		if v.Namespace == "bip122" {
			parsed, err := ParseBitcoinAddress(v.Reference, v.Account)
			if err != nil || string(parsed.Kind) != v.Kind || HexOf(parsed.Payload) != v.PayloadHex {
				t.Errorf("%s: %+v (%v), want %s %s", v.Name, parsed, err, v.Kind, v.PayloadHex)
			}
		}
		valid[v.Namespace]++
	}
	for _, ns := range []string{"bip122", "solana", "cosmos"} {
		if valid[ns] < 4 || refused[ns] < 4 {
			t.Errorf("%s: %d valid and %d refused vectors, want at least 4 of each", ns, valid[ns], refused[ns])
		}
	}
}

// the chain-profile vectors of the identifier sections: a valid DID's account is its own canonical spelling, a refused one is refused or re-spelled
func TestTheChainIdentifierVectorsAreJudgedAsCoreJudgesThem(t *testing.T) {
	set := loadVectors(t)
	chain := 0
	for _, p := range set.Parse {
		parts := strings.Split(p.Input, ":")
		if len(parts) != 7 || parts[3] != "chain" {
			continue
		}
		chain++
		got, err := NormalizeChainAccount(parts[4], parts[5], parts[6])
		switch {
		case p.Valid && (err != nil || got != parts[6]):
			t.Errorf("%s: account %q normalizes to %q (%v), a valid DID names its canonical account", p.Name, parts[6], got, err)
		case !p.Valid && p.Refusal == "profile-semantics" && !errors.Is(err, ErrInvalidAccount):
			t.Errorf("%s: %q was accepted (%v), core refuses it as profile-semantics", p.Name, p.Input, err)
		case !p.Valid && p.Refusal == "non-canonical" && (err != nil || got == parts[6]):
			t.Errorf("%s: %q is read as canonical (%q, %v), core refuses the spelling", p.Name, parts[6], got, err)
		}
	}
	if chain < 12 {
		t.Errorf("the set carries %d chain identifier vectors, want at least 12", chain)
	}
	for _, c := range set.Construct {
		if c.Profile != "chain" {
			continue
		}
		account, err := NormalizeChainAccount(c.Args[0], c.Args[1], c.Args[2])
		if err != nil || !strings.HasSuffix(c.Canonical, ":"+account) {
			t.Errorf("%s: %v normalizes to %q (%v), the construct vector's canonical DID is %s", c.Name, c.Args, account, err, c.Canonical)
		}
	}
}

func TestKeccak256AndTheEIP55ChecksumAgreeWithTheirPublishedExamples(t *testing.T) {
	for input, want := range map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	} {
		if got := keccak256([]byte(input)); hex.EncodeToString(got[:]) != want {
			t.Errorf("keccak256(%q) = %x, want %s", input, got, want)
		}
	}
	// a multi-block input (the sponge's rate is 136 bytes) is a function of the whole input, and a block boundary is not special
	for _, size := range []int{135, 136, 137, 200, 272} {
		a, b := keccak256(bytes.Repeat([]byte{'a'}, size)), keccak256(bytes.Repeat([]byte{'a'}, size+1))
		if a == b || a != keccak256(bytes.Repeat([]byte{'a'}, size)) {
			t.Errorf("keccak256 of %d bytes is not a distinct, stable function of its input", size)
		}
	}
	// EIP-55's own examples
	for _, address := range []string{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"} {
		got, err := NormalizeChainAccount("eip155", "1", address)
		if err != nil || got != strings.ToLower(address) {
			t.Errorf("%s: %q %v", address, got, err)
		}
		// one flipped letter case breaks the checksum and the address is refused, never lower-cased into a valid-looking identity
		for i := 2; i < len(address); i++ {
			c := address[i]
			if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				flipped := address[:i] + string(c^0x20) + address[i+1:]
				if _, err := NormalizeChainAccount("eip155", "1", flipped); !errors.Is(err, ErrInvalidAccount) {
					t.Errorf("%s with the case of position %d flipped was accepted: %v", address, i, err)
				}
			}
		}
	}
	for _, address := range []string{"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"} {
		if got, err := NormalizeChainAccount("eip155", "1", address); err != nil || got != "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed" {
			t.Errorf("%s: %q %v", address, got, err)
		}
	}
}

func TestTheBase58AndBase58CheckCodecsAreExactInversesAndRefuseWhatTheyShould(t *testing.T) {
	for _, h := range []string{"", "00", "0000", "00ff", "ff", "0100", "62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "000000000019d6689c085ae165831e93"} {
		raw, _ := hex.DecodeString(h)
		if back := Base58Decode(Base58Encode(raw)); !bytes.Equal(back, raw) {
			t.Errorf("%q: round trip %x", h, back)
		}
	}
	if Base58Decode("0OIl") != nil {
		t.Error("characters outside the alphabet were decoded")
	}
	version, payload, ok := Base58CheckDecode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	if !ok || version != 0 || HexOf(payload) != "62e907b15cbf27d5425399ebf6f0fb50ebb88f18" || Base58CheckEncode(payload, version) != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("the genesis coinbase address: %d %x %v", version, payload, ok)
	}
	if _, _, ok := Base58CheckDecode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"); ok {
		t.Error("a mutated checksum was accepted")
	}
	if _, _, ok := Base58CheckDecode("1111"); ok {
		t.Error("a string shorter than a version and a checksum was accepted")
	}
}

func TestTheBitRegroupingRefusesNonCanonicalPaddingAsBIP173Says(t *testing.T) {
	if got, err := ConvertBits([]byte{0xff}, 8, 5, true); err != nil || !bytes.Equal(got, []byte{31, 28}) {
		t.Errorf("8 to 5 with padding: %v %v", got, err)
	}
	if got, err := ConvertBits([]byte{31, 31, 31, 31, 31, 31, 31, 31}, 5, 8, false); err != nil || !bytes.Equal(got, []byte{255, 255, 255, 255, 255}) {
		t.Errorf("5 to 8 exact: %v %v", got, err)
	}
	for name, in := range map[string][]byte{"non-zero padding": {31, 31, 31, 31, 31, 31, 31, 31, 31}, "a whole group of padding": {0, 0, 0, 0, 0, 0, 0, 0, 0}, "a value above the group width": {32}} {
		if _, err := ConvertBits(in, 5, 8, false); !errors.Is(err, ErrInvalidAccount) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEveryRefusalNamesTheNamespaceTheReferenceAndTheAccountRules(t *testing.T) {
	const mainnet = "000000000019d6689c085ae165831e93"
	for name, c := range map[string]struct{ ns, ref, account, contains string }{
		"a namespace outside the closed list":                 {"tezos", "1", "tz1", "is not one of"},
		"a reference of the wrong form":                       {"eip155", "01", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "is not a valid eip155 chain reference"},
		"an account of the wrong form":                        {"eip155", "1", "0x5aae", "is not a valid eip155 account"},
		"a bech32 address of the wrong prefix for the chain":  {"cosmos", "osmosis-1", "cosmos1syavy2npfyt9tcncdtsdzf7kny9lh777pahuux", "uses \"osmo\""},
		"a solana key of 31 bytes":                            {"solana", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", Base58Encode(make([]byte, 31)), "is not a valid solana account"},
		"a bitcoin network the method does not register":      {"bip122", "12a765e31ffd4059bada1e25190f6e98", "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL", "registry entry"},
		"a future witness version":                            {"bip122", mainnet, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "only P2WPKH"},
		"witness version 0 with a bech32m checksum":           {"bip122", mainnet, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "version 0 is bech32"},
		"witness version 1 with a bech32 checksum":            {"bip122", mainnet, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "are bech32m"},
		"a base58check address of another version byte (WIF)": {"bip122", mainnet, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "holds 32 bytes, want 20"},
	} {
		if _, err := NormalizeChainAccount(c.ns, c.ref, c.account); !errors.Is(err, ErrInvalidAccount) || !strings.Contains(err.Error(), c.contains) {
			t.Errorf("%s: %v, want ErrInvalidAccount containing %q", name, err, c.contains)
		}
	}
}

// the solana normalizer itself (past the shape check): a 33-byte key and a non-canonical spelling are refused by name
func TestTheSolanaStandardRefusesWhatTheShapeCheckAdmits(t *testing.T) {
	thirtyThree := Base58Encode(append([]byte{1}, make([]byte, 32)...))
	if _, err := NormalizeChainAccount("solana", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", thirtyThree); !errors.Is(err, ErrInvalidAccount) || !strings.Contains(err.Error(), "want a 32-byte public key") {
		t.Errorf("a 33-byte key: %v", err)
	}
	for _, key := range []string{"11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"} {
		if got, err := NormalizeChainAccount("solana", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", key); err != nil || got != key {
			t.Errorf("%s: %q %v", key, got, err)
		}
	}
}

// THE BOUNDARIES (part 25f2, row D3): the planted cuts of this package found what the vectors do not reach, exactly as the cuts of core's chain_accounts.go did: the edges of the human-readable part's
// byte range and length, the string length and the reason it gives, the regrouping width, the refusals the shape check in front of a normalizer shadows, and the reason each refusal gives.

func TestTheHumanReadablePartIsHeldToItsByteRangeAndLengthAtTheirEdges(t *testing.T) {
	for _, ok := range []string{"!", "~", "!~", "a", strings.Repeat("a", 83), "?"} {
		if err := bech32CheckHRP(ok); err != nil {
			t.Errorf("the human-readable part %q (every byte in 33..126, 1 to 83 characters) was refused: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{"empty": "", "84 characters": strings.Repeat("a", 84), "a space (32)": "a b", "DEL (127)": "a\x7fb", "a byte above 127": "a\x80b", "a control byte": "\x01"} {
		if err := bech32CheckHRP(bad); !errors.Is(err, ErrInvalidAccount) {
			t.Errorf("%s: %q: %v", name, bad, err)
		}
	}
	for _, hrp := range []string{"!", "~", strings.Repeat("a", 83)} {
		s, err := Bech32Encode(hrp, []byte{1, 2}, Bech32)
		if err != nil {
			t.Fatal(err)
		}
		if got, _, _, err := Bech32Decode(s, Bech32MaxLength); err != nil || got != hrp {
			t.Errorf("%q: decoded to %q (%v)", hrp, got, err)
		}
	}
	if _, err := Bech32Encode("UPPER", nil, Bech32); err == nil || !strings.Contains(err.Error(), "lower-case") {
		t.Errorf("an upper-case human-readable part was encoded: %v", err)
	}
}

func TestTheEncoderRefusesAValueThatIsNotAFiveBitGroupAndAcceptsTheLargestThatIs(t *testing.T) {
	if _, err := Bech32Encode("x", []byte{32}, Bech32); err == nil || !strings.Contains(err.Error(), "5-bit group") {
		t.Errorf("a value of 32: %v", err)
	}
	s, err := Bech32Encode("x", []byte{31, 0}, Bech32)
	if err != nil {
		t.Fatalf("a value of 31: %v", err)
	}
	if _, data, _, err := Bech32Decode(s, Bech32MaxLength); err != nil || !bytes.Equal(data, []byte{31, 0}) {
		t.Errorf("31 and 0 decode to %v (%v)", data, err)
	}
}

func TestTheStringLengthIsHeldToItsBoundsAndSaysSo(t *testing.T) {
	message := "characters, want 8 to"
	if _, _, _, err := Bech32Decode("abcdefg", 90); err == nil || !strings.Contains(err.Error(), message) {
		t.Errorf("a seven-character string: %v, want the length refusal", err)
	}
	if _, _, _, err := Bech32Decode("a12uel5l", 90); err != nil {
		t.Errorf("the eight-character minimum: %v", err)
	}
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i % 32)
	}
	long, err := Bech32Encode("x", data, Bech32)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Bech32Decode(long, len(long)); err != nil {
		t.Errorf("a string of exactly the maximum length: %v", err)
	}
	if _, _, _, err := Bech32Decode(long, len(long)-1); err == nil || !strings.Contains(err.Error(), message) {
		t.Errorf("a string one character over the maximum: %v, want the length refusal", err)
	}
	if _, _, _, err := Bech32Decode(long, Bech32MaxLength); err != nil {
		t.Errorf("the same string under the codec's own maximum: %v", err)
	}
}

func TestTheBitRegroupingNamesAValueThatDoesNotFitAndPadsExactlyWhenBitsRemain(t *testing.T) {
	if _, err := ConvertBits([]byte{32, 0, 0, 0, 0, 0, 0, 0}, 5, 8, false); err == nil || !strings.Contains(err.Error(), "does not fit its source group width") {
		t.Errorf("a 5-bit group of 32: %v", err)
	}
	if _, err := ConvertBits([]byte{31, 0, 0, 0, 0, 0, 0, 0}, 5, 8, false); err != nil {
		t.Errorf("a 5-bit group of 31: %v", err)
	}
	// five bytes are eight groups exactly: padding adds none; one byte is one group and three bits: padding adds a second
	if got, err := ConvertBits([]byte{1, 2, 3, 4, 5}, 8, 5, true); err != nil || len(got) != 8 {
		t.Errorf("five bytes with padding: %v %v", got, err)
	}
	if got, err := ConvertBits([]byte{1}, 8, 5, true); err != nil || len(got) != 2 {
		t.Errorf("one byte with padding: %v %v", got, err)
	}
}

func TestTheBase58CheckDecoderHoldsItsMinimumLengthAndItsChecksum(t *testing.T) {
	// a version byte and an empty payload are the shortest base58check string, and its checksum decides
	version, payload, ok := Base58CheckDecode(Base58CheckEncode(nil, 7))
	if !ok || version != 7 || len(payload) != 0 {
		t.Errorf("the shortest base58check string: %d %x %v", version, payload, ok)
	}
	// four bytes that are exactly the checksum of an empty body are NOT a base58check string (too short for a version byte)
	if _, _, ok := Base58CheckDecode(Base58Encode(doubleSHA256(nil))); ok {
		t.Error("a string of only a checksum was read as base58check")
	}
	if _, _, ok := Base58CheckDecode("0OIl"); ok {
		t.Error("characters outside the alphabet were read as base58check")
	}
}

func TestTheCosmosNormalizerRefusesEachThingForItsOwnReason(t *testing.T) {
	raw := make([]byte, 20)
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	data, err := ConvertBits(raw, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := Bech32Encode("cosmos", data, Bech32)
	if _, err := normalizeCosmosAccount("cosmoshub-4", strings.ToUpper(good)); err == nil || !strings.Contains(err.Error(), "lower case only") {
		t.Errorf("an upper-case address reaches the normalizer and is refused for its case: %v", err)
	}
	if _, err := normalizeCosmosAccount("cosmoshub-4", good[:len(good)-1]+"q"); err == nil || !strings.Contains(err.Error(), "checksum does not verify") {
		t.Errorf("a bad checksum is refused for the checksum: %v", err)
	}
	padded, _ := Bech32Encode("cosmos", append(append([]byte(nil), data...), 0, 1), Bech32)
	if _, err := normalizeCosmosAccount("cosmoshub-4", padded); err == nil || !strings.Contains(err.Error(), "padding") {
		t.Errorf("an address with non-zero padding: %v", err)
	}
	for _, size := range []int{19, 21, 31, 33} {
		d, _ := ConvertBits(make([]byte, size), 8, 5, true)
		s, _ := Bech32Encode("cosmos", d, Bech32)
		if _, err := normalizeCosmosAccount("cosmoshub-4", s); err == nil || !strings.Contains(err.Error(), "holds") {
			t.Errorf("a payload of %d bytes: %v", size, err)
		}
	}
}

func TestEveryBitcoinRefusalGivesItsOwnReason(t *testing.T) {
	const mainnet = "000000000019d6689c085ae165831e93"
	reason := func(reference, account, contains string) {
		t.Helper()
		if _, err := ParseBitcoinAddress(reference, account); err == nil || !errors.Is(err, ErrInvalidAccount) || !strings.Contains(err.Error(), contains) {
			t.Errorf("%s: %v, want a refusal containing %q", account, err, contains)
		}
	}
	reason(mainnet, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "neither")
	for _, size := range []int{19, 21} {
		reason(mainnet, Base58CheckEncode(make([]byte, size), 0x00), "holds")
	}
	reason(mainnet, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "checksum does not verify")
	foreign, _ := Bech32Encode("bc1x", []byte{0, 1, 2, 3}, Bech32)
	reason(mainnet, foreign, "human-readable part")
	reason(mainnet, "bc1gmk9yu", "carries no witness version")
	versionOnly, _ := Bech32Encode("bc", []byte{0}, Bech32)
	reason(mainnet, versionOnly, "0-byte program")
	pad := append([]byte{0}, make([]byte, 33)...)
	pad[len(pad)-1] = 1
	padded, _ := Bech32Encode("bc", pad, Bech32)
	reason(mainnet, padded, "padding")
	reason(mainnet, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "version 0 is bech32")
	reason(mainnet, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "bech32m")
	reason("000000000933ea01ad0ee984209779ba", "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", "bech32m")
	reason(mainnet, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "only P2WPKH")
}
