// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Command identity-starter is the deterministic, fully OFFLINE identity
// walkthrough (DX P1-5): DID → issue VC → present a VP → verify → revoke, with
// no node and no network. It uses the published contract types
// (infrix-schema/credential) and the standalone verifier
// (infrix-verify/credverify) — the same code a third party runs. Fixed key seeds
// make every run byte-identical.
//
//	go run ./examples/identity-starter
//
// Exit 0 when every expected outcome holds; non-zero otherwise.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/opendlt/infrix-schema/credential"
	"github.com/opendlt/infrix-verify/credverify"
)

// did derives the canonical did:infrix for an Accumulate ADI (offline, the same
// deterministic transform the SDK/CLI use).
func did(adi string) string { return "did:infrix:acc://" + adi }

// signVC signs a credential with the issuer key (Ed25519 over the proof-omitted
// signing content) and attaches the proof.
func signVC(vc *credential.VerifiableCredential, priv ed25519.PrivateKey, vm string) error {
	content, err := vc.SigningContent()
	if err != nil {
		return err
	}
	vc.Proof = &credential.Proof{
		Type:               "Ed25519Signature2020",
		VerificationMethod: vm,
		ProofValue:         hex.EncodeToString(ed25519.Sign(priv, content)),
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "identity-starter FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("\nidentity-starter: all steps behaved as expected (offline, deterministic).")
}

func run() error {
	// Deterministic keys (fixed seeds) → identical output every run.
	issuerPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	issuerPub := issuerPriv.Public().(ed25519.PublicKey)
	holderPub := holderPriv.Public().(ed25519.PublicKey)

	issuerDID, issuerVM := did("issuer.acme"), did("issuer.acme")+"#key-1"
	holderDID, holderVM := did("alice.acme"), did("alice.acme")+"#key-1"

	// 1. DIDs (offline: a DID is a deterministic function of the ADI).
	fmt.Println("1. DIDs")
	fmt.Println("   issuer:", issuerDID)
	fmt.Println("   holder:", holderDID)

	// 2. Issue a verifiable credential and sign it.
	vc := &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/ns/credentials/v2"},
		ID:           "urn:vc:kyc-alice-1",
		Type:         []string{"VerifiableCredential", "KYCCredential"},
		Issuer:       issuerDID,
		IssuanceDate: "2026-01-01T00:00:00Z",
		CredentialSubject: map[string]any{
			"id":   holderDID,
			"tier": "2",
			"age":  "25",
		},
	}
	if err := signVC(vc, issuerPriv, issuerVM); err != nil {
		return fmt.Errorf("sign VC: %w", err)
	}
	fmt.Println("\n2. Issued VC", vc.ID, "→ signed by", issuerDID)

	// Trust anchor: the verifier resolves issuer/holder keys the caller vouches
	// for (here, our fixed test keys). It never trusts keys inside the credential.
	issuerKeys := credverify.Options{ResolveIssuerKey: func(_, _ string) (ed25519.PublicKey, error) {
		return issuerPub, nil
	}}
	holderResolver := func(_, _ string) (ed25519.PublicKey, error) { return holderPub, nil }

	// 3. Verify the credential independently.
	rep := credverify.VerifyCredential(vc, issuerKeys)
	fmt.Println("\n3. VerifyCredential →", verdict(rep.Verified))
	if !rep.Verified {
		return fmt.Errorf("freshly-issued credential should verify: %+v", rep.Checks)
	}

	// 4. Holder presents the VC in a challenge-bound VP; verify it.
	const challenge = "verifier-nonce-2026"
	vp := &credential.VerifiablePresentation{
		Type:                 []string{"VerifiablePresentation"},
		Holder:               holderDID,
		VerifiableCredential: []credential.VerifiableCredential{*vc},
	}
	content, err := vp.SigningContent(challenge)
	if err != nil {
		return fmt.Errorf("VP signing content: %w", err)
	}
	vp.Proof = &credential.Proof{
		Type:               "Ed25519Signature2020",
		VerificationMethod: holderVM,
		Challenge:          challenge,
		ProofValue:         hex.EncodeToString(ed25519.Sign(holderPriv, content)),
	}
	vpRep := credverify.VerifyPresentation(vp, challenge, issuerKeys, holderResolver)
	fmt.Println("\n4. VerifyPresentation (challenge-bound) →", verdict(vpRep.Verified))
	if !vpRep.Verified {
		return fmt.Errorf("presentation should verify: %+v", vpRep.Checks)
	}
	// A replay under a different challenge must fail.
	replay := credverify.VerifyPresentation(vp, "different-nonce", issuerKeys, holderResolver)
	fmt.Println("   replay under a different challenge →", verdict(replay.Verified), "(must be INVALID)")
	if replay.Verified {
		return fmt.Errorf("VP replay under a mismatched challenge must NOT verify")
	}

	// 5. Revoke the credential; verification now fails closed.
	revokedOpts := issuerKeys
	revokedOpts.IsRevoked = func(id string) bool { return id == vc.ID }
	revRep := credverify.VerifyCredential(vc, revokedOpts)
	fmt.Println("\n5. After revocation, VerifyCredential →", verdict(revRep.Verified), "(must be INVALID)")
	if revRep.Verified {
		return fmt.Errorf("revoked credential must NOT verify")
	}

	// 6. Tamper detection: any change to a signed claim breaks verification.
	tampered := *vc
	tampered.CredentialSubject = map[string]any{"id": holderDID, "tier": "9", "age": "25"}
	tRep := credverify.VerifyCredential(&tampered, issuerKeys)
	fmt.Println("\n6. Tampered claim, VerifyCredential →", verdict(tRep.Verified), "(must be INVALID)")
	if tRep.Verified {
		return fmt.Errorf("tampered credential must NOT verify")
	}
	return nil
}

func verdict(ok bool) string {
	if ok {
		return "VALID"
	}
	return "INVALID"
}
