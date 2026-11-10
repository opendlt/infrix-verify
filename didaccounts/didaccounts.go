// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package didaccounts is the account standard of the chain namespaces of did:infrix (the same rules as infrix core, pkg/did/chain_accounts.go), node-free and standard-library only.
//
// A chain-profile DID, did:infrix:v1:chain:<namespace>:<reference>:<account>, names an account on a foreign chain, and a verifier that compares an address recovered from a signature with the DID's
// account compares it with the account's ONE canonical spelling. This package decides that spelling and refuses what no chain could hold, by each chain's own address standard:
//
//	eip155   a 20-byte address, canonical lower-case, the EIP-55 checksum checked when the address is mixed-case
//	cosmos   a bech32 address (BIP-173): the checksum, the human-readable part and the payload length (20 or 32 bytes), lower case only
//	solana   a base58 encoding of exactly 32 bytes in its one canonical spelling
//	bip122   a Bitcoin address of the network the CAIP-2 reference names: base58check P2PKH and P2SH, segwit P2WPKH and P2WSH (version 0, bech32) and P2TR (version 1, bech32m)
//
// The bech32 and bech32m codec is BIP-173 and BIP-350, base58 and base58check are Bitcoin's, and the legacy Keccak-256 of the EIP-55 checksum is implemented here because the module depends on
// the standard library only (the verifier-isolation fence). The package is held to the shared vector set (credverify/testdata/did-vectors-v1.json: the `bech32` and `chainAccounts` sections that
// `infrix did vectors` exports from the Go side of infrix core, the source) and to the standards' own published vectors.
package didaccounts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// ErrInvalidAccount is every refusal of this package: an account no chain of its namespace could hold.
var ErrInvalidAccount = errors.New("invalid chain account")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAccount, fmt.Sprintf(format, args...))
}

// ---- base58 and base58check ----

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Decode returns the bytes of a base58 string, or nil when it holds a character outside the alphabet. Leading '1's are leading zero bytes.
func Base58Decode(text string) []byte {
	value := new(big.Int)
	fiftyEight := big.NewInt(58)
	for i := 0; i < len(text); i++ {
		digit := strings.IndexByte(base58Alphabet, text[i])
		if digit < 0 {
			return nil
		}
		value.Mul(value, fiftyEight)
		value.Add(value, big.NewInt(int64(digit)))
	}
	zeros := 0
	for zeros < len(text) && text[zeros] == '1' {
		zeros++
	}
	return append(make([]byte, zeros), value.Bytes()...)
}

// Base58Encode is the base58 spelling of bytes (each leading zero byte is a leading '1').
func Base58Encode(raw []byte) string {
	value := new(big.Int).SetBytes(raw)
	fiftyEight, mod := big.NewInt(58), new(big.Int)
	var digits []byte
	for value.Sign() > 0 {
		value.DivMod(value, fiftyEight, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}
	zeros := 0
	for zeros < len(raw) && raw[zeros] == 0 {
		zeros++
	}
	out := strings.Repeat("1", zeros)
	for i := len(digits) - 1; i >= 0; i-- {
		out += string(digits[i])
	}
	return out
}

func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// Base58CheckDecode returns the version byte and the payload of a base58check string, or ok=false when it is not one (a character outside the alphabet, too short, a checksum that does not verify).
func Base58CheckDecode(text string) (version byte, payload []byte, ok bool) {
	raw := Base58Decode(text)
	if raw == nil || len(raw) < 5 {
		return 0, nil, false
	}
	body, sum := raw[:len(raw)-4], raw[len(raw)-4:]
	want := doubleSHA256(body)
	for i := 0; i < 4; i++ {
		if sum[i] != want[i] {
			return 0, nil, false
		}
	}
	return body[0], append([]byte(nil), body[1:]...), true
}

// Base58CheckEncode is the base58check spelling of a payload under a version byte.
func Base58CheckEncode(payload []byte, version byte) string {
	body := append([]byte{version}, payload...)
	return Base58Encode(append(body, doubleSHA256(body)...))
}

// ---- bech32 and bech32m (BIP-173, BIP-350) ----

// Variant is which checksum a bech32 string carries.
type Variant int

const (
	// Bech32 is the BIP-173 checksum (constant 1).
	Bech32 Variant = iota + 1
	// Bech32m is the BIP-350 checksum (constant 0x2bc830a3).
	Bech32m
)

const (
	bech32Charset   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32mConstant = 0x2bc830a3
	// Bech32MaxLength is the longest string the codec accepts unless the caller asks for less: Cosmos addresses are far shorter.
	Bech32MaxLength = 255
)

func bech32Polymod(values []byte) uint32 {
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generator {
			if (top>>uint(i))&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32CheckHRP(hrp string) error {
	if len(hrp) < 1 || len(hrp) > 83 {
		return refuse("bech32: the human-readable part is %d characters, want 1 to 83", len(hrp))
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return refuse("bech32: the human-readable part holds a character outside 33..126 at %d", i)
		}
	}
	return nil
}

// Bech32Encode encodes a lower-case human-readable part and 5-bit data groups; the result is lower case.
func Bech32Encode(hrp string, data []byte, variant Variant) (string, error) {
	if err := bech32CheckHRP(hrp); err != nil {
		return "", err
	}
	if strings.ToLower(hrp) != hrp {
		return "", refuse("bech32: the human-readable part must be lower-case to be encoded")
	}
	constant := uint32(1)
	if variant == Bech32m {
		constant = bech32mConstant
	}
	values := append(append(bech32HRPExpand(hrp), data...), 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ constant
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	all := append([]byte(nil), data...)
	for i := 0; i < 6; i++ {
		all = append(all, byte((polymod>>uint(5*(5-i)))&31))
	}
	for _, d := range all {
		if d > 31 {
			return "", refuse("bech32: a data value is not a 5-bit group")
		}
		b.WriteByte(bech32Charset[d])
	}
	return b.String(), nil
}

// Bech32Decode decodes a bech32 or bech32m string: the lower-case human-readable part, the 5-bit data groups without the checksum and which checksum verified. The string must be all lower case or
// all upper case (mixed case is invalid), between 8 and maxLength characters, with the separator last and at least six checksum characters after it.
func Bech32Decode(s string, maxLength int) (string, []byte, Variant, error) {
	if len(s) < 8 || len(s) > maxLength {
		return "", nil, 0, refuse("bech32: the string is %d characters, want 8 to %d", len(s), maxLength)
	}
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, 0, refuse("bech32: the string mixes upper and lower case")
	}
	s = lower
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, 0, refuse("bech32: the separator is missing, leaves no human-readable part or leaves fewer than six checksum characters")
	}
	hrp := s[:pos]
	if err := bech32CheckHRP(hrp); err != nil {
		return "", nil, 0, err
	}
	data := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		index := strings.IndexByte(bech32Charset, s[i])
		if index < 0 {
			return "", nil, 0, refuse("bech32: %q is not a character of the charset", s[i])
		}
		data = append(data, byte(index))
	}
	switch bech32Polymod(append(bech32HRPExpand(hrp), data...)) {
	case 1:
		return hrp, data[:len(data)-6], Bech32, nil
	case bech32mConstant:
		return hrp, data[:len(data)-6], Bech32m, nil
	}
	return "", nil, 0, refuse("bech32: the checksum does not verify")
}

// ConvertBits regroups a byte string between bit widths (BIP-173's convertbits). With pad false any leftover bits must be zero and fewer than the source width, or the encoding is not the one canonical
// spelling of its bytes.
func ConvertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, v := range data {
		if uint32(v)>>from != 0 {
			return nil, refuse("a value does not fit its source group width")
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, refuse("the padding bits are not zero, or a whole group of padding remains")
	}
	return out, nil
}

// ---- cosmos ----

// cosmosHRP is the human-readable part of the chain ids this package knows. A chain id outside the table is not refused: the standard binds a prefix to no chain id.
var cosmosHRP = map[string]string{
	"cosmoshub-4": "cosmos", "theta-testnet-001": "cosmos", "osmosis-1": "osmo", "osmo-test-5": "osmo", "juno-1": "juno", "stargaze-1": "stars", "akashnet-2": "akash",
	"secret-4": "secret", "noble-1": "noble", "neutron-1": "neutron", "injective-1": "inj", "dydx-mainnet-1": "dydx",
}

func normalizeCosmosAccount(reference, account string) (string, error) {
	if account != strings.ToLower(account) {
		return "", refuse("cosmos account %q is not lower-case, and a Cosmos address is spelled in lower case only", account)
	}
	hrp, data, variant, err := Bech32Decode(account, Bech32MaxLength)
	if err != nil {
		return "", err
	}
	if variant != Bech32 {
		return "", refuse("cosmos account %q carries a bech32m checksum, and a Cosmos address is bech32", account)
	}
	if want, known := cosmosHRP[reference]; known && hrp != want {
		return "", refuse("cosmos account %q has the prefix %q, and chain %s uses %q", account, hrp, reference, want)
	}
	payload, err := ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", err
	}
	if len(payload) != 20 && len(payload) != 32 {
		return "", refuse("cosmos account %q holds %d bytes, want 20 (an account) or 32 (a module, an interchain account or a contract)", account, len(payload))
	}
	return account, nil
}

// ---- solana ----

func normalizeSolanaAccount(_, account string) (string, error) {
	raw := Base58Decode(account)
	if len(raw) != 32 {
		return "", refuse("solana account %q decodes to %d bytes, want a 32-byte public key", account, len(raw))
	}
	if Base58Encode(raw) != account {
		return "", refuse("solana account %q is not the canonical base58 spelling of its 32 bytes", account)
	}
	return account, nil
}

// ---- bip122 (Bitcoin) ----

// BitcoinAddressKind names the address types a bip122 account may be.
type BitcoinAddressKind string

// The address types.
const (
	BitcoinP2PKH  BitcoinAddressKind = "p2pkh"
	BitcoinP2SH   BitcoinAddressKind = "p2sh"
	BitcoinP2WPKH BitcoinAddressKind = "p2wpkh"
	BitcoinP2WSH  BitcoinAddressKind = "p2wsh"
	BitcoinP2TR   BitcoinAddressKind = "p2tr"
)

type bitcoinNetwork struct {
	name                      string
	hrp                       string
	p2pkhVersion, p2shVersion byte
}

// bitcoinNetworks are the Bitcoin networks by the CAIP-2 reference of namespace bip122: the first 32 hexadecimal characters of the genesis block hash.
var bitcoinNetworks = map[string]bitcoinNetwork{
	"000000000019d6689c085ae165831e93": {"mainnet", "bc", 0x00, 0x05},
	"000000000933ea01ad0ee984209779ba": {"testnet", "tb", 0x6f, 0xc4},
	"00000008819873e925422c1ff0f99f7c": {"signet", "tb", 0x6f, 0xc4},
	"0f9188f13cb7b2c71f2a335e3a4fc328": {"regtest", "bcrt", 0x6f, 0xc4},
}

// BitcoinAddress is a bip122 account read by the standard: what kind it is and the hash or key it commits to (20 bytes for P2PKH, P2SH and P2WPKH, 32 for P2WSH and P2TR).
type BitcoinAddress struct {
	Kind    BitcoinAddressKind
	Payload []byte
	Network string
}

// ParseBitcoinAddress reads a Bitcoin address of the network the CAIP-2 reference names, by the address standards. Any other address is refused by name.
func ParseBitcoinAddress(reference, account string) (BitcoinAddress, error) {
	network, ok := bitcoinNetworks[reference]
	if !ok {
		return BitcoinAddress{}, refuse("bip122 reference %q is not a Bitcoin network this method registers (mainnet 000000000019d6689c085ae165831e93, testnet 000000000933ea01ad0ee984209779ba, signet, regtest): another chain is a registry entry", reference)
	}
	if strings.HasPrefix(strings.ToLower(account), network.hrp+"1") {
		return parseSegwitAddress(network, account)
	}
	version, payload, ok := Base58CheckDecode(account)
	if !ok {
		return BitcoinAddress{}, refuse("bip122 account %q is neither a %s segwit address nor a base58check address", account, network.name)
	}
	if len(payload) != 20 {
		return BitcoinAddress{}, refuse("bip122 account %q holds %d bytes, want 20", account, len(payload))
	}
	if Base58CheckEncode(payload, version) != account {
		return BitcoinAddress{}, refuse("bip122 account %q is not the canonical base58check spelling of its bytes", account)
	}
	switch version {
	case network.p2pkhVersion:
		return BitcoinAddress{Kind: BitcoinP2PKH, Payload: payload, Network: network.name}, nil
	case network.p2shVersion:
		return BitcoinAddress{Kind: BitcoinP2SH, Payload: payload, Network: network.name}, nil
	}
	return BitcoinAddress{}, refuse("bip122 account %q has the version byte 0x%02x, which is neither the P2PKH (0x%02x) nor the P2SH (0x%02x) version of %s", account, version, network.p2pkhVersion, network.p2shVersion, network.name)
}

func parseSegwitAddress(network bitcoinNetwork, account string) (BitcoinAddress, error) {
	hrp, data, variant, err := Bech32Decode(account, 90)
	if err != nil {
		return BitcoinAddress{}, err
	}
	if hrp != network.hrp {
		return BitcoinAddress{}, refuse("bip122 account %q has the human-readable part %q, and %s uses %q", account, hrp, network.name, network.hrp)
	}
	if len(data) < 1 {
		return BitcoinAddress{}, refuse("bip122 account %q carries no witness version", account)
	}
	witnessVersion := data[0]
	program, err := ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return BitcoinAddress{}, err
	}
	switch {
	case witnessVersion == 0 && variant == Bech32 && len(program) == 20:
		return BitcoinAddress{Kind: BitcoinP2WPKH, Payload: program, Network: network.name}, nil
	case witnessVersion == 0 && variant == Bech32 && len(program) == 32:
		return BitcoinAddress{Kind: BitcoinP2WSH, Payload: program, Network: network.name}, nil
	case witnessVersion == 1 && variant == Bech32m && len(program) == 32:
		return BitcoinAddress{Kind: BitcoinP2TR, Payload: program, Network: network.name}, nil
	case witnessVersion == 0 && variant != Bech32:
		return BitcoinAddress{}, refuse("bip122 account %q is witness version 0 with a bech32m checksum (BIP-350: version 0 is bech32)", account)
	case witnessVersion != 0 && variant != Bech32m:
		return BitcoinAddress{}, refuse("bip122 account %q is witness version %d with a bech32 checksum (BIP-350: versions 1 and above are bech32m)", account, witnessVersion)
	}
	return BitcoinAddress{}, refuse("bip122 account %q is witness version %d with a %d-byte program: only P2WPKH (version 0, 20 bytes), P2WSH (version 0, 32 bytes) and P2TR (version 1, 32 bytes) are accounts", account, witnessVersion, len(program))
}

func normalizeBitcoinAccount(reference, account string) (string, error) {
	parsed, err := ParseBitcoinAddress(reference, account)
	if err != nil {
		return "", err
	}
	switch parsed.Kind {
	case BitcoinP2WPKH, BitcoinP2WSH, BitcoinP2TR:
		return strings.ToLower(account), nil
	}
	return account, nil
}

// ---- eip155 ----

func normalizeEIP155Account(_, account string) (string, error) {
	hexPart := account[2:]
	if hexPart != strings.ToLower(hexPart) && hexPart != strings.ToUpper(hexPart) && !eip55ChecksumValid(hexPart) {
		return "", refuse("eip155 account %q is mixed-case with an invalid EIP-55 checksum", account)
	}
	return "0x" + strings.ToLower(hexPart), nil
}

func eip55ChecksumValid(hexPart string) bool {
	sum := keccak256([]byte(strings.ToLower(hexPart)))
	for i, c := range hexPart {
		nibble := sum[i/2] >> 4
		if i%2 == 1 {
			nibble = sum[i/2] & 0x0f
		}
		switch {
		case c >= 'a' && c <= 'f':
			if nibble >= 8 {
				return false
			}
		case c >= 'A' && c <= 'F':
			if nibble < 8 {
				return false
			}
		}
	}
	return true
}

// ---- the namespaces ----

type namespace struct {
	reference, account *regexp.Regexp
	normalize          func(reference, account string) (string, error)
}

var namespaces = map[string]namespace{
	"eip155": {regexp.MustCompile(`^(0|[1-9][0-9]{0,31})$`), regexp.MustCompile(`^0[xX][0-9a-fA-F]{40}$`), normalizeEIP155Account},
	"cosmos": {regexp.MustCompile(`^[-a-zA-Z0-9]{1,32}$`), regexp.MustCompile(`^[a-z0-9]{1,83}1[02-9ac-hj-np-z]{6,}$`), normalizeCosmosAccount},
	"solana": {regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32}$`), regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`), normalizeSolanaAccount},
	"bip122": {regexp.MustCompile(`^[0-9a-f]{32}$`), regexp.MustCompile(`^[a-zA-Z0-9]{26,90}$`), normalizeBitcoinAccount},
}

// Namespaces lists the CAIP-2 namespaces of did:infrix v1, sorted.
func Namespaces() []string { return []string{"bip122", "cosmos", "eip155", "solana"} }

// NormalizeChainAccount validates a chain account by its namespace's standard and returns it in its one canonical spelling: an eip155 address in lower case, a segwit address in lower case, every other
// account as it is. An account no chain of the namespace could hold is refused (ErrInvalidAccount).
func NormalizeChainAccount(namespaceName, reference, account string) (string, error) {
	ns, ok := namespaces[namespaceName]
	if !ok {
		return "", refuse("namespace %q is not one of %v", namespaceName, Namespaces())
	}
	if !ns.reference.MatchString(reference) {
		return "", refuse("reference %q is not a valid %s chain reference", reference, namespaceName)
	}
	if !ns.account.MatchString(account) {
		return "", refuse("account %q is not a valid %s account", account, namespaceName)
	}
	return ns.normalize(reference, account)
}

// HexOf is the lower-case hexadecimal of bytes (a convenience for callers that compare a program or a hash).
func HexOf(raw []byte) string { return hex.EncodeToString(raw) }
