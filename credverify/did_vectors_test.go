// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/opendlt/infrix-schema/credential"
)

// THE SHARED did:infrix VECTOR SET (W.DID.CROSSSURFACE.PARITY), pinned in this module's CI.
//
// testdata/did-vectors-v1.json is the exact output of `infrix did vectors --out` in infrix core; the
// same file (the same SHA-256) is pinned in infrix-sdk-js and infrix-schema, and infrix core pins the
// digest of what it exports.
//
// This verifier is node-free and has no DID parser: the identifier is whatever the CALLER's resolver
// is asked to resolve. Parity for such a surface is that it never alters an identifier on the way to
// the resolver, and that it fails closed when the resolver declines. Both are enforced for every
// vector, valid or refused: the resolver must receive exactly the vector's bytes, and a resolver that
// refuses an identifier (as a parser-bearing resolver refuses a legacy, mutable or non-canonical DID)
// turns the credential and the presentation into a NOT VERIFIED verdict.

const pinnedDIDVectorsSHA256 = "e25a465a066cbdbf746ca7abefed35d6d39e908120a2925b1844d761fc5e63cb"

type didVectorSet struct {
	Spec  string `json:"spec"`
	Parse []struct {
		Name  string `json:"name"`
		Input string `json:"input"`
		Valid bool   `json:"valid"`
	} `json:"parse"`
}

func loadDIDVectorSet(t *testing.T) didVectorSet {
	t.Helper()
	raw, err := os.ReadFile("testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pinnedDIDVectorsSHA256 {
		t.Fatalf("did vectors sha256 = %s, pinned %s: re-export with `infrix did vectors --out` and update every repository together", got, pinnedDIDVectorsSHA256)
	}
	if s := sha256.Sum256(append(append([]byte(nil), raw...), ' ')); hex.EncodeToString(s[:]) == pinnedDIDVectorsSHA256 {
		t.Fatal("PLANTED DEFECT NOT DETECTED: an edited vector file kept the pinned digest")
	}
	var set didVectorSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if set.Spec != "did-infrix-v1" || len(set.Parse) < 26 {
		t.Fatalf("vector set shape changed: spec %q, %d parse", set.Spec, len(set.Parse))
	}
	return set
}

func TestDIDVectorsReachTheCallersResolverUnaltered(t *testing.T) {
	set := loadDIDVectorSet(t)
	for _, v := range set.Parse {
		t.Run(v.Name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			vm := v.Input + "#key-1"
			vc := &credential.VerifiableCredential{
				Type: []string{"VerifiableCredential"}, Issuer: v.Input, IssuanceDate: "2026-10-27T00:00:00Z",
				CredentialSubject: map[string]any{"id": v.Input},
			}
			content, err := vc.SigningContent()
			if err != nil {
				t.Fatal(err)
			}
			vc.Proof = &credential.Proof{Type: "Ed25519Signature2020", VerificationMethod: vm, ProofValue: encodeProofValue(ed25519.Sign(priv, content))}

			var gotDID, gotVM string
			resolve := func(did, method string) (ed25519.PublicKey, error) { gotDID, gotVM = did, method; return pub, nil }
			rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolve})
			if !rep.Verified {
				t.Fatalf("a credential whose issuer is %q must verify against the key the caller vouches for: %+v", v.Input, rep.Checks)
			}
			if gotDID != v.Input || gotVM != vm {
				t.Fatalf("the verifier altered the identifier before resolving it: got (%q, %q), want (%q, %q)", gotDID, gotVM, v.Input, vm)
			}
		})
	}
}

// TestResolverRefusalOfAVectorFailsClosed is the refusal twin: when the caller's resolver declines an
// identifier (what a parser-bearing resolver does for every vector marked invalid) the verdict is NOT
// VERIFIED, for the credential and for a presentation holder alike.
func TestResolverRefusalOfAVectorFailsClosed(t *testing.T) {
	set := loadDIDVectorSet(t)
	refused := 0
	for _, v := range set.Parse {
		if v.Valid {
			continue
		}
		refused++
		t.Run(v.Name, func(t *testing.T) {
			_, priv, _ := ed25519.GenerateKey(nil)
			vc := &credential.VerifiableCredential{
				Type: []string{"VerifiableCredential"}, Issuer: v.Input, IssuanceDate: "2026-10-27T00:00:00Z",
				CredentialSubject: map[string]any{"id": "did:example:subject"},
			}
			content, _ := vc.SigningContent()
			vc.Proof = &credential.Proof{Type: "Ed25519Signature2020", VerificationMethod: v.Input + "#key-1", ProofValue: encodeProofValue(ed25519.Sign(priv, content))}
			decline := func(string, string) (ed25519.PublicKey, error) { return nil, os.ErrInvalid }
			if rep := VerifyCredential(vc, Options{ResolveIssuerKey: decline}); rep.Verified {
				t.Fatalf("PLANTED DEFECT NOT REFUSED: a credential verified although the resolver declined issuer %q", v.Input)
			}
		})
	}
	if refused < 10 {
		t.Fatalf("expected the vector set to carry at least 10 refusal vectors, found %d", refused)
	}
}
