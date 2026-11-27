// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// THE ACCUMULATE USER SIGNATURE TYPES THIS VERIFIER CHECKS (core brief 28cq row 2, KNOWN-LIMITS L3185): every type an Infrix approval may be signed
// as, which is every type its governance half is signed as. Each is checked the way Accumulate's executor checks it (protocol.<Type>Signature.Verify
// through verifySig), with the verifier's own code: the signed message is SHA-256(metadataHash || messageHash) for every type but legacyED25519, whose
// is SHA-256(metadataHash || uvarint(timestamp) || messageHash) (protocol.SignLegacyED25519: common.Uint64Bytes is the uvarint).

// userSignatureTypes maps the type name to its protocol.SignatureType value.
var userSignatureTypes = map[string]uint64{
	"legacyED25519": 1,
	"ed25519":       2,
	"rcd1":          3,
	"btc":           8,
	"btcLegacy":     9,
	"eth":           10,
	"rsaSha256":     14,
	"ecdsaSha256":   15,
}

// UserSignatureTypeNames is the user signature types this verifier checks, sorted.
func UserSignatureTypeNames() []string {
	out := make([]string, 0, len(userSignatureTypes))
	for n := range userSignatureTypes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func userSignatureTypeName(v uint64) (string, bool) {
	for n, t := range userSignatureTypes {
		if t == v {
			return n, true
		}
	}
	return "", false
}

// ErrUserSignatureTypeUnknown is a signature type this verifier does not check.
var ErrUserSignatureTypeUnknown = errors.New("not an Accumulate user signature type this verifier checks")

// VerifyUserSignature checks sig by pub, of type sigType, over messageHash with the signature's metadata hash (and, for legacyED25519, its
// timestamp), exactly as Accumulate's executor does. A nil error is a signature that verifies.
func VerifyUserSignature(sigType string, pub, sig, metadataHash, messageHash []byte, timestamp uint64) error {
	if _, ok := userSignatureTypes[sigType]; !ok {
		return fmt.Errorf("%w: %q (want one of %v)", ErrUserSignatureTypeUnknown, sigType, UserSignatureTypeNames())
	}
	if len(metadataHash) != sha256.Size || len(messageHash) != sha256.Size {
		return fmt.Errorf("a %s signature is checked over a 32-byte metadata hash and a 32-byte message hash", sigType)
	}
	var digest [32]byte
	if sigType == "legacyED25519" {
		digest = sha256.Sum256(append(binary.AppendUvarint(append([]byte(nil), metadataHash...), timestamp), messageHash...))
	} else {
		digest = sha256.Sum256(append(append([]byte(nil), metadataHash...), messageHash...))
	}
	switch sigType {
	case "legacyED25519", "ed25519", "rcd1":
		if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("a %s signature needs a %d-byte key and a %d-byte signature (have %d and %d)", sigType, ed25519.PublicKeySize, ed25519.SignatureSize, len(pub), len(sig))
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig) {
			return fmt.Errorf("the %s signature does not verify", sigType)
		}
		return nil
	case "btc", "btcLegacy":
		pk, err := secp256k1.ParsePubKey(pub)
		if err != nil {
			return fmt.Errorf("the %s public key does not parse: %v", sigType, err)
		}
		s, err := secpecdsa.ParseDERSignature(sig)
		if err != nil {
			return fmt.Errorf("the %s signature is not strict DER: %v", sigType, err)
		}
		if !s.Verify(digest[:], pk) {
			return fmt.Errorf("the %s signature does not verify", sigType)
		}
		return nil
	case "eth":
		pk, err := secp256k1.ParsePubKey(pub)
		if err != nil {
			return fmt.Errorf("the %s public key does not parse: %v", sigType, err)
		}
		if len(sig) != 64 && len(sig) != 65 {
			return fmt.Errorf("an %s signature is 64 or 65 bytes (r||s[||v]), got %d", sigType, len(sig))
		}
		var r, s secp256k1.ModNScalar
		if overflow := r.SetByteSlice(sig[:32]); overflow || r.IsZero() {
			return fmt.Errorf("the %s signature's r is out of range", sigType)
		}
		if overflow := s.SetByteSlice(sig[32:64]); overflow || s.IsZero() {
			return fmt.Errorf("the %s signature's s is out of range", sigType)
		}
		// Accumulate verifies an eth signature with go-ethereum's VerifySignature, which refuses the malleable upper-half s (the strict rule a
		// network running upstream Accumulate applies; Infrix's signers emit the lower half only).
		if s.IsOverHalfOrder() {
			return fmt.Errorf("the %s signature has a malleable upper-half s", sigType)
		}
		if !secpecdsa.NewSignature(&r, &s).Verify(digest[:], pk) {
			return fmt.Errorf("the %s signature does not verify", sigType)
		}
		return nil
	case "rsaSha256":
		pk, err := x509.ParsePKCS1PublicKey(pub)
		if err != nil {
			return fmt.Errorf("the %s public key is not PKCS #1 DER: %v", sigType, err)
		}
		if pk.Size() != len(sig) {
			return fmt.Errorf("the %s signature is %d bytes; the key's modulus is %d", sigType, len(sig), pk.Size())
		}
		if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("the %s signature does not verify", sigType)
		}
		return nil
	case "ecdsaSha256":
		k, err := x509.ParsePKIXPublicKey(pub)
		if err != nil {
			return fmt.Errorf("the %s public key is not PKIX DER: %v", sigType, err)
		}
		pk, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("the %s public key is a %T, not an ECDSA key", sigType, k)
		}
		if !ecdsa.VerifyASN1(pk, digest[:], sig) {
			return fmt.Errorf("the %s signature does not verify", sigType)
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUserSignatureTypeUnknown, sigType)
}
