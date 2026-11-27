// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// governanceSigningVector is core's shared governance-half vector (core pkg/l0/proofcapture/testdata/governance-signing-vectors.json, written by
// the Go encoder over Accumulate's own signers and copied here byte-identical): the fields this verifier checks.
type governanceSigningVector struct {
	Name            string `json:"name"`
	SignatureType   string `json:"signatureType"`
	Timestamp       uint64 `json:"timestamp"`
	PublicKey       string `json:"publicKey"`
	KeyHash         string `json:"keyHash"`
	TransactionHash string `json:"transactionHash"`
	Signature       string `json:"signature"`
	MetadataHash    string `json:"metadataHash"`
}

func mustHex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

// TestS28cqEveryApprovalSignatureTypeVerifiesFromCoresSharedVectors (core brief 28cq row 2, KNOWN-LIMITS L3185): for every governance half in core's
// vectors (every approval signature type, as initiator and co-signer) this verifier decodes the signature, recomputes the metadata hash Accumulate
// hashes, verifies the signature over the transaction with its own code, and computes the key hash the page holds; a signature of each type with
// one bit of its value flipped does not verify.
func TestS28cqEveryApprovalSignatureTypeVerifiesFromCoresSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/governance-signing-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []governanceSigningVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range vs {
		sig := mustHex(t, v.Name, v.Signature)
		s, err := decodeUserSignature(sig)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if s.Type != v.SignatureType {
			t.Fatalf("%s: decoded a %s signature; the vector is %s", v.Name, s.Type, v.SignatureType)
		}
		if !bytes.Equal(s.PublicKey, mustHex(t, v.Name, v.PublicKey)) || s.Timestamp != v.Timestamp {
			t.Fatalf("%s: the decoded key or timestamp is not the vector's", v.Name)
		}
		md := sha256.Sum256(s.Metadata)
		if hex.EncodeToString(md[:]) != v.MetadataHash {
			t.Fatalf("%s: metadata hash %x; the vector's is %s", v.Name, md, v.MetadataHash)
		}
		txHash := mustHex(t, v.Name, v.TransactionHash)
		if err := VerifyUserSignature(s.Type, s.PublicKey, s.Signature, md[:], txHash, s.Timestamp); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		kh, err := KeyHash(s.Type, s.PublicKey)
		if err != nil || hex.EncodeToString(kh) != v.KeyHash {
			t.Fatalf("%s: key hash %x (%v); the vector's is %s", v.Name, kh, err, v.KeyHash)
		}
		bad := append([]byte(nil), s.Signature...)
		bad[len(bad)/2] ^= 0x01
		if err := VerifyUserSignature(s.Type, s.PublicKey, bad, md[:], txHash, s.Timestamp); err == nil {
			t.Fatalf("%s: a %s signature with a flipped bit verified", v.Name, s.Type)
		}
		seen[s.Type] = true
	}
	for _, n := range UserSignatureTypeNames() {
		if !seen[n] {
			t.Fatalf("core's vectors carry no %s governance half", n)
		}
	}
}
