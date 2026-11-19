// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// multikeyDoc is a document whose one verification method is the key as an Ed25519 Multikey.
func multikeyDoc(t *testing.T, typ string, key ed25519.PublicKey) json.RawMessage {
	t.Helper()
	mb := "z" + didaccounts.Base58Encode(append([]byte{0xed, 0x01}, key...))
	raw, err := json.Marshal(map[string]any{"id": "d", "verificationMethod": []map[string]any{{"id": "d#k", "type": typ, "controller": "d", "publicKeyMultibase": mb}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestARecoveryKeyTheDocumentsListIsRefusedAtTheDeactivation holds the rule core enforces since part 28e (statementchain.CommitmentListed): a deactivation whose reactivation
// commitment is the SHA-256 of an Ed25519 key a version of the documents lists is refused by name; a fresh key and a final deactivation are accepted.
func TestARecoveryKeyTheDocumentsListIsRefusedAtTheDeactivation(t *testing.T) {
	old, _, _ := ed25519.GenerateKey(rand.Reader)
	current, _, _ := ed25519.GenerateKey(rand.Reader)
	fresh, _, _ := ed25519.GenerateKey(rand.Reader)
	history := func(commitTo ed25519.PublicKey) []*Entry {
		genesis := &Entry{DID: "d", NetworkID: "n", DocumentHash: []byte{1}, Sequence: 1, VersionID: "1", Scheme: SchemeEd25519, StorageHash: []byte{9}, Document: multikeyDoc(t, "Multikey", old)}
		rotate := &Entry{DID: "d", NetworkID: "n", DocumentHash: []byte{2}, Sequence: 2, VersionID: "2", Scheme: SchemeEd25519, PredecessorStorageHash: []byte{9}, StorageHash: []byte{10},
			Operations: []Operation{{Type: "addService", Object: map[string]json.RawMessage{}}}, Document: multikeyDoc(t, "Ed25519VerificationKey2020", current)}
		object := map[string]json.RawMessage{}
		if commitTo != nil {
			sum := sha256.Sum256(commitTo)
			object[MemberReactivationCommitment], _ = json.Marshal(base64.StdEncoding.EncodeToString(sum[:]))
		}
		deactivate := &Entry{DID: "d", NetworkID: "n", DocumentHash: []byte{2}, Sequence: 3, VersionID: "3", Scheme: SchemeEd25519, PredecessorStorageHash: []byte{10}, StorageHash: []byte{11},
			Deactivated: true, Operations: []Operation{{Type: OperationDeactivate, Object: object}}, Document: rotate.Document}
		return []*Entry{genesis, rotate, deactivate}
	}
	for name, key := range map[string]ed25519.PublicKey{"the current key": current, "a key an earlier version listed": old} {
		if err := Verify("d", "n", history(key), cutAcceptAll{}); !errors.Is(err, ErrRecoveryKeyListed) {
			t.Errorf("a commitment to %s: %v", name, err)
		}
	}
	if err := Verify("d", "n", history(fresh), cutAcceptAll{}); err != nil {
		t.Errorf("a commitment to a fresh key: %v", err)
	}
	if err := Verify("d", "n", history(nil), cutAcceptAll{}); err != nil {
		t.Errorf("a final deactivation: %v", err)
	}
	if keys := listedEd25519Keys(json.RawMessage(`not json`)); keys != nil {
		t.Errorf("a document that does not decode listed %d keys", len(keys))
	}
	if keys := listedEd25519Keys(multikeyDoc(t, "EcdsaSecp256k1VerificationKey2019", old)); keys != nil {
		t.Errorf("a method of another type listed %d keys", len(keys))
	}
}
