// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/opendlt/infrix-schema/credential"
)

const (
	issuerDID = "did:infrix:acc://issuer.acme"
	issuerVM  = "did:infrix:acc://issuer.acme#key-1"
	holderDID = "did:infrix:acc://alice.acme"
	holderVM  = "did:infrix:acc://alice.acme#key-1"
)

func signVC(t *testing.T, vc *credential.VerifiableCredential, priv ed25519.PrivateKey, vm string) {
	t.Helper()
	content, err := vc.SigningContent() // proof omitted internally
	if err != nil {
		t.Fatalf("signing content: %v", err)
	}
	vc.Proof = &credential.Proof{
		Type:               "Ed25519Signature2020",
		VerificationMethod: vm,
		ProofValue:         hex.EncodeToString(ed25519.Sign(priv, content)),
	}
}

func sampleVC() *credential.VerifiableCredential {
	return &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/ns/credentials/v2"},
		ID:           "urn:vc:kyc-1",
		Type:         []string{"VerifiableCredential", "KYCCredential"},
		Issuer:       issuerDID,
		IssuanceDate: "2026-01-01T00:00:00Z",
		CredentialSubject: map[string]any{
			"id":   holderDID,
			"tier": "2",
		},
	}
}

func resolverFor(pub ed25519.PublicKey) KeyResolver {
	return func(_, _ string) (ed25519.PublicKey, error) { return pub, nil }
}

func TestVerifyCredential_ValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	signVC(t, vc, priv, issuerVM)

	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if !rep.Verified {
		t.Fatalf("expected verified, checks=%+v", rep.Checks)
	}
	if rep.Issuer != issuerDID || rep.Subject != holderDID {
		t.Errorf("issuer/subject = %q/%q", rep.Issuer, rep.Subject)
	}
}

func TestVerifyCredential_TamperedClaimFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	signVC(t, vc, priv, issuerVM)
	vc.CredentialSubject["tier"] = "9" // tamper AFTER signing

	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if rep.Verified {
		t.Fatal("tampered credential must not verify")
	}
}

func TestVerifyCredential_WrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	signVC(t, vc, priv, issuerVM)

	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(otherPub)})
	if rep.Verified {
		t.Fatal("signature under a different key must not verify")
	}
}

func TestVerifyCredential_FailsClosedWithoutResolver(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	signVC(t, vc, priv, issuerVM)

	rep := VerifyCredential(vc, Options{}) // no resolver
	if rep.Verified {
		t.Fatal("must fail closed when no issuer key resolver is supplied")
	}
}

func TestVerifyCredential_Expiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	vc.ExpirationDate = "2026-06-01T00:00:00Z"
	signVC(t, vc, priv, issuerVM)

	future := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub), Now: future}).Verified {
		t.Fatal("expired credential must not verify")
	}
	past := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if !VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub), Now: past}).Verified {
		t.Fatal("unexpired credential should verify")
	}
}

func TestVerifyCredential_Revocation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	vc := sampleVC()
	signVC(t, vc, priv, issuerVM)

	revoked := VerifyCredential(vc, Options{
		ResolveIssuerKey: resolverFor(pub),
		IsRevoked:        func(id string) bool { return id == "urn:vc:kyc-1" },
	})
	if revoked.Verified {
		t.Fatal("revoked credential must not verify")
	}
}

func TestVerifyPresentation_RoundTrip(t *testing.T) {
	issPub, issPriv, _ := ed25519.GenerateKey(nil)
	holdPub, holdPriv, _ := ed25519.GenerateKey(nil)

	vc := sampleVC()
	signVC(t, vc, issPriv, issuerVM)

	const challenge = "verifier-nonce-123"
	vp := &credential.VerifiablePresentation{
		Type:                 []string{"VerifiablePresentation"},
		Holder:               holderDID,
		VerifiableCredential: []credential.VerifiableCredential{*vc},
	}
	content, err := vp.SigningContent(challenge)
	if err != nil {
		t.Fatalf("vp signing content: %v", err)
	}
	vp.Proof = &credential.Proof{
		Type:               "Ed25519Signature2020",
		VerificationMethod: holderVM,
		Challenge:          challenge,
		ProofValue:         hex.EncodeToString(ed25519.Sign(holdPriv, content)),
	}

	issuerOpts := Options{ResolveIssuerKey: resolverFor(issPub)}
	rep := VerifyPresentation(vp, challenge, issuerOpts, resolverFor(holdPub))
	if !rep.Verified {
		t.Fatalf("expected VP verified, checks=%+v", rep.Checks)
	}

	// Wrong challenge must fail closed (replay protection).
	if VerifyPresentation(vp, "different-nonce", issuerOpts, resolverFor(holdPub)).Verified {
		t.Fatal("VP with a mismatched challenge must not verify")
	}
}
