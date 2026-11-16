// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// THE NAMESPACE VERIFIERS OF THE CHAIN PROFILE, the second implementation of infrix core's pkg/did/chain_verifiers.go (part 25g, rows H1 and H3). A chain-profile DID names an account on a
// foreign chain, and the only authority over its history is that account's key in its chain's own message-signing standard. What the account signs is the STATEMENT MESSAGE
//
//	"infrix:did-statement:v1:" || lower-case hexadecimal of the 32-byte statement digest          (88 ASCII bytes)
//
// and each namespace verifies it by its standard, exactly as core does:
//
//	eip155  eip155:eip191   EIP-191 personal_sign: keccak256("\x19Ethereum Signed Message:\n" || decimal length || message); 65 bytes r || s || v (v 27/28 or 0/1), low s; the signer is the
//	                        recovered key, 65 bytes uncompressed; the account is the last 20 bytes of keccak256 of its 64 coordinate bytes.
//	solana  solana:ed25519  Ed25519 over the message; the signer is the account's own 32-byte key (the account is its base58).
//	bip122  bip122:bip137   double SHA-256 of varstr("Bitcoin Signed Message:\n") || varstr(message); 65 bytes header || r || s; P2PKH (headers 27-30 uncompressed, 31-34 compressed) and P2WPKH
//	                        (39-42, compressed) verified, P2SH-P2WPKH (35-38), P2SH, P2WSH and P2TR refused by name; HASH160 of the recovered key in the header's form is the address's hash.
//	cosmos  cosmos:adr036   SHA-256 of the ADR-036 amino sign document (canonical JSON) carrying the message in base64 and the account as signer; 64 bytes r || s, low s; the signer is the
//	                        33-byte compressed key and the account is the bech32 of its HASH160 under the account's own prefix (a 32-byte address is refused by name).

// ChainStatementMessagePrefix begins the statement message a foreign account signs.
const ChainStatementMessagePrefix = "infrix:did-statement:v1:"

// ChainStatementMessage is the message a foreign account signs for a statement digest.
func ChainStatementMessage(digest [32]byte) []byte {
	return []byte(ChainStatementMessagePrefix + hex.EncodeToString(digest[:]))
}

// The schemes of the chain profile, one per namespace.
const (
	ChainSchemeEIP155 = "eip155:eip191"
	ChainSchemeSolana = "solana:ed25519"
	ChainSchemeBIP122 = "bip122:bip137"
	ChainSchemeCosmos = "cosmos:adr036"
)

// ErrChainSignature is a statement signature the namespace's verifier does not accept.
var ErrChainSignature = errors.New("the signature is not the foreign account's under its chain's message-signing standard")

func chainRefuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrChainSignature, fmt.Sprintf(format, args...))
}

// ChainAccount is a chain-profile DID's account: its CAIP-2 namespace and reference, and the account in its one canonical spelling.
type ChainAccount struct {
	Namespace, Reference, Account string
}

// ErrNotChainDID is a DID that is not a canonical chain-profile DID.
var ErrNotChainDID = errors.New("not a canonical did:infrix:v1:chain DID")

// ParseChainDID reads did:infrix:v1:chain:<namespace>:<reference>:<account>, holding the account to its namespace's standard (didaccounts) and to its one canonical spelling.
func ParseChainDID(did string) (ChainAccount, error) {
	parts := strings.Split(did, ":")
	if len(parts) != 7 || parts[0] != "did" || parts[1] != "infrix" || parts[2] != "v1" || parts[3] != "chain" {
		return ChainAccount{}, fmt.Errorf("%w: %q", ErrNotChainDID, did)
	}
	canonical, err := didaccounts.NormalizeChainAccount(parts[4], parts[5], parts[6])
	if err != nil {
		return ChainAccount{}, fmt.Errorf("%w: %q: %v", ErrNotChainDID, did, err)
	}
	if canonical != parts[6] {
		return ChainAccount{}, fmt.Errorf("%w: %q: the account's canonical spelling is %s", ErrNotChainDID, did, canonical)
	}
	return ChainAccount{Namespace: parts[4], Reference: parts[5], Account: canonical}, nil
}

// NamespaceVerifier verifies that a chain-profile DID's account signed a message in its namespace's standard.
type NamespaceVerifier interface {
	Scheme() string
	Verify(account ChainAccount, message, signer, signature []byte) error
}

// chainVerifiers is the closed registry: exactly one verifier per namespace of didaccounts.Namespaces.
var chainVerifiers = map[string]NamespaceVerifier{"eip155": eip155Verifier{}, "solana": solanaVerifier{}, "bip122": bip122Verifier{}, "cosmos": cosmosVerifier{}}

// ChainVerifierNamespaces lists the namespaces with a verifier, sorted.
func ChainVerifierNamespaces() []string {
	out := make([]string, 0, len(chainVerifiers))
	for ns := range chainVerifiers {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// ChainVerifier is the verifier of a namespace.
func ChainVerifier(namespace string) (NamespaceVerifier, bool) {
	v, ok := chainVerifiers[namespace]
	return v, ok
}

// recoverKey recovers the key of r || s with a recovery id over a hash, as a chain refusal when it does not.
func recoverKey(rs []byte, recovery byte, hash []byte) (secpPoint, error) {
	key, err := RecoverSecp256k1(rs, recovery, hash)
	if err != nil {
		return secpPoint{}, chainRefuse("%v", err)
	}
	return key, nil
}

// ---- eip155 ----

type eip155Verifier struct{}

func (eip155Verifier) Scheme() string { return ChainSchemeEIP155 }

// EIP191PersonalMessageHash is the hash personal_sign signs for a message (EIP-191 version 0x45).
func EIP191PersonalMessageHash(message []byte) []byte {
	sum := didaccounts.Keccak256(append([]byte("\x19Ethereum Signed Message:\n"+strconv.Itoa(len(message))), message...))
	return sum[:]
}

// ethereumAddress is the canonical account of a key: 0x and the lower-case hexadecimal of the last 20 bytes of keccak256 of its 64 coordinate bytes.
func ethereumAddress(key secpPoint) string {
	sum := didaccounts.Keccak256(key.serializeUncompressed()[1:])
	return "0x" + hex.EncodeToString(sum[12:])
}

func (eip155Verifier) Verify(account ChainAccount, message, signer, signature []byte) error {
	if len(signature) != 65 {
		return chainRefuse("an eip155 signature is 65 bytes r || s || v, got %d", len(signature))
	}
	v := signature[64]
	switch {
	case v == 27 || v == 28:
		v -= 27
	case v == 0 || v == 1:
	default:
		return chainRefuse("v is %d, want 27 or 28 (or 0 or 1)", signature[64])
	}
	key, err := recoverKey(signature[:64], v, EIP191PersonalMessageHash(message))
	if err != nil {
		return err
	}
	if !bytes.Equal(signer, key.serializeUncompressed()) {
		return chainRefuse("the signer is not the public key the signature recovers (%x)", key.serializeUncompressed())
	}
	if got := ethereumAddress(key); got != account.Account {
		return chainRefuse("the signature recovers address %s, the DID names %s", got, account.Account)
	}
	return nil
}

// ---- solana ----

type solanaVerifier struct{}

func (solanaVerifier) Scheme() string { return ChainSchemeSolana }

func (solanaVerifier) Verify(account ChainAccount, message, signer, signature []byte) error {
	key := didaccounts.Base58Decode(account.Account)
	if len(key) != ed25519.PublicKeySize {
		return chainRefuse("the solana account %s is not a 32-byte public key", account.Account)
	}
	if !bytes.Equal(signer, key) {
		return chainRefuse("the signer %x is not the account's public key %x", signer, key)
	}
	if len(signature) != ed25519.SignatureSize {
		return chainRefuse("an Ed25519 signature is %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(key, message, signature) {
		return chainRefuse("the Ed25519 signature does not verify under the account's key")
	}
	return nil
}

// ---- bip122 ----

type bip122Verifier struct{}

func (bip122Verifier) Scheme() string { return ChainSchemeBIP122 }

// BitcoinMessageHash is double SHA-256 of varstr("Bitcoin Signed Message:\n") || varstr(message).
func BitcoinMessageHash(message []byte) []byte {
	var buf bytes.Buffer
	writeVarString(&buf, []byte("Bitcoin Signed Message:\n"))
	writeVarString(&buf, message)
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])
	return second[:]
}

// writeVarString writes Bitcoin's CompactSize of len(b) and b.
func writeVarString(buf *bytes.Buffer, b []byte) {
	n := uint64(len(b))
	switch {
	case n < 0xfd:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.Write([]byte{0xfd, byte(n), byte(n >> 8)})
	case n <= 0xffffffff:
		buf.Write([]byte{0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
	default:
		buf.Write([]byte{0xff, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24), byte(n >> 32), byte(n >> 40), byte(n >> 48), byte(n >> 56)})
	}
	buf.Write(b)
}

func (bip122Verifier) Verify(account ChainAccount, message, signer, signature []byte) error {
	address, err := didaccounts.ParseBitcoinAddress(account.Reference, account.Account)
	if err != nil {
		return chainRefuse("the account is not a Bitcoin address of its network: %v", err)
	}
	switch address.Kind {
	case didaccounts.BitcoinP2PKH, didaccounts.BitcoinP2WPKH:
	case didaccounts.BitcoinP2SH:
		return chainRefuse("a P2SH account (%s) is not verified by this method: a script hash proves no key without its script", account.Account)
	default:
		return chainRefuse("a %s account (%s) signs by BIP-322, which this method does not verify", address.Kind, account.Account)
	}
	if len(signature) != 65 {
		return chainRefuse("a Bitcoin message signature is 65 bytes header || r || s, got %d", len(signature))
	}
	header := signature[0]
	var compressed bool
	var kind didaccounts.BitcoinAddressKind
	switch {
	case header >= 27 && header <= 30:
		kind = didaccounts.BitcoinP2PKH
	case header >= 31 && header <= 34:
		kind, compressed = didaccounts.BitcoinP2PKH, true
	case header >= 35 && header <= 38:
		return chainRefuse("header %d names a P2SH-P2WPKH signature, which this method does not verify", header)
	case header >= 39 && header <= 42:
		kind, compressed = didaccounts.BitcoinP2WPKH, true
	default:
		return chainRefuse("header %d is not a BIP-137 header (27 to 42)", header)
	}
	if kind != address.Kind {
		return chainRefuse("header %d names a %s signature, the account %s is %s", header, kind, account.Account, address.Kind)
	}
	key, err := recoverKey(signature[1:], (header-27)%4, BitcoinMessageHash(message))
	if err != nil {
		return err
	}
	serialized := key.serializeUncompressed()
	if compressed {
		serialized = key.serializeCompressed()
	}
	if !bytes.Equal(signer, serialized) {
		return chainRefuse("the signer is not the public key the signature recovers (%x)", serialized)
	}
	if got := Hash160(serialized); !bytes.Equal(got, address.Payload) {
		return chainRefuse("the signature recovers key hash %x, the account %s commits to %x", got, account.Account, address.Payload)
	}
	return nil
}

// ---- cosmos ----

type cosmosVerifier struct{}

func (cosmosVerifier) Scheme() string { return ChainSchemeCosmos }

// CosmosADR036SignDoc is the amino JSON sign document ADR-036 signs for a message and a signer address, in the canonical form (members sorted, no whitespace).
func CosmosADR036SignDoc(message []byte, signer string) []byte {
	// the document is made of strings, arrays and objects only, so it always has a canonical form
	value, _ := CanonicalJSON(map[string]any{
		"account_number": "0", "chain_id": "", "fee": map[string]any{"amount": []any{}, "gas": "0"}, "memo": "", "sequence": "0",
		"msgs": []any{map[string]any{"type": "sign/MsgSignData", "value": map[string]any{"data": base64.StdEncoding.EncodeToString(message), "signer": signer}}},
	})
	return value
}

func (cosmosVerifier) Verify(account ChainAccount, message, signer, signature []byte) error {
	hrp, data, _, err := didaccounts.Bech32Decode(account.Account, didaccounts.Bech32MaxLength)
	if err != nil {
		return chainRefuse("the cosmos account %s is not bech32: %v", account.Account, err)
	}
	if payload, err := didaccounts.ConvertBits(data, 5, 8, false); err != nil || len(payload) != 20 {
		return chainRefuse("the cosmos account %s is not a 20-byte account address (a module, interchain or contract address holds no key and signs nothing)", account.Account)
	}
	if len(signer) != 33 {
		return chainRefuse("the signer is %d bytes, want a 33-byte compressed secp256k1 public key", len(signer))
	}
	key, err := ParseSecp256k1PublicKey(signer)
	if err != nil {
		return chainRefuse("the signer is not a secp256k1 public key: %v", err)
	}
	program, _ := didaccounts.ConvertBits(Hash160(signer), 8, 5, true)
	if got, err := didaccounts.Bech32Encode(hrp, program, didaccounts.Bech32); err != nil || got != account.Account {
		return chainRefuse("the signer's address under %q is %s, the DID names %s", hrp, got, account.Account)
	}
	hash := sha256.Sum256(CosmosADR036SignDoc(message, account.Account))
	if !VerifySecp256k1(key, hash[:], signature) {
		return chainRefuse("the secp256k1 signature does not verify over the ADR-036 sign document (64 bytes r || s, low s)")
	}
	return nil
}
