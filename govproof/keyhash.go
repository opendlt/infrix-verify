// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Accumulate's BTC key hash is RIPEMD-160 (protocol.BTCHash)
	"golang.org/x/crypto/sha3"
)

// KeyHash is protocol.PublicKeyHash for every Accumulate user signature type this verifier checks (the type name without the "accumulate-"
// prefix): SHA-256 of the key for ed25519, legacyED25519, rsaSha256 and ecdsaSha256; the RCD hash SHA-256(SHA-256(0x01 || key)) for rcd1
// (protocol.GetRCDHashFromPublicKey, version 1); RIPEMD-160(SHA-256(key)) of the key as carried for btc and btcLegacy (protocol.BTCHash); the last 20
// bytes of Keccak-256 of the uncompressed key without its prefix for eth (protocol.ETHhash).
func KeyHash(sigType string, pub []byte) ([]byte, error) {
	switch sigType {
	case "ed25519", "legacyED25519", "rsaSha256", "ecdsaSha256":
		h := sha256.Sum256(pub)
		return h[:], nil
	case "rcd1":
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("an rcd1 key is %d bytes, not %d", ed25519.PublicKeySize, len(pub))
		}
		h := sha256.Sum256(append([]byte{1}, pub...))
		h = sha256.Sum256(h[:])
		return h[:], nil
	case "btc", "btcLegacy":
		if _, err := secp256k1.ParsePubKey(pub); err != nil {
			return nil, err
		}
		s := sha256.Sum256(pub)
		h := ripemd160.New()
		h.Write(s[:])
		return h.Sum(nil), nil
	case "eth":
		k, err := secp256k1.ParsePubKey(pub)
		if err != nil {
			return nil, err
		}
		h := sha3.NewLegacyKeccak256()
		h.Write(k.SerializeUncompressed()[1:])
		return h.Sum(nil)[12:], nil
	default:
		return nil, fmt.Errorf("signature type %q has no key hash this verifier computes, so its key cannot be proven on a page", sigType)
	}
}
