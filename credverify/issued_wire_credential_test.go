// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/credential"
)

// A CREDENTIAL SIGNED OVER THE ISSUER'S BYTES, NOT OVER THIS MODULE'S STRUCT.
//
// Every other test in this package signs with vc.SigningContent(), so signer
// and verifier share one struct and agree with each other by construction —
// a field the schema fails to model is dropped on BOTH sides and the signature
// still verifies. That is the self-agreement that hid this defect: until
// infrix-schema v0.6.0, CredentialStatus did not declare revocationListIndex
// or revocationListCredential, which the Infrix issuer emits on every
// credential carrying a status. Parsing dropped them, re-marshalling produced
// different bytes from the signed ones, and this verifier rejected every such
// credential as "signature does not verify" while every signature was valid.
//
// Here the signed document is a literal in the issuer's exact wire form (field
// order and all), signed as bytes. Nothing on the signing side touches the
// schema types, so a schema that is lossy for an issued credential fails this
// test instead of agreeing with itself.

// issuedUnsignedJSON is what the issuer hashes: the credential with no proof
// member at all.
const issuedUnsignedJSON = `{"@context":["https://www.w3.org/2018/credentials/v1"],` +
	`"id":"urn:uuid:deadbeefdeadbeef:1","type":["VerifiableCredential","RoundTripCredential"],` +
	`"issuer":"did:infrix:issuer","issuanceDate":"2026-09-10T00:00:00Z",` +
	`"credentialSubject":{"id":"did:infrix:subject","role":"auditor"},` +
	`"credentialStatus":{"id":"did:infrix:issuer/status#0","type":"StatusList2021Entry",` +
	`"revocationListIndex":"0","revocationListCredential":"did:infrix:issuer/status"}}`

// signIssuedBytes signs the literal and splices the proof in the way an issuer
// serialises it, returning the bytes an integrator receives.
func signIssuedBytes(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(issuedUnsignedJSON))
	proof, err := json.Marshal(map[string]string{
		"type":               "Ed25519Signature2020",
		"verificationMethod": "did:infrix:issuer#key-1",
		"proofPurpose":       "assertionMethod",
		"proofValue":         encodeProofValue(ed25519.Sign(priv, digest[:])),
	})
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	return []byte(strings.TrimSuffix(issuedUnsignedJSON, "}") + `,"proof":` + string(proof) + "}")
}

// TestAStatusBearingCredentialSignedByTheIssuerVerifies is the claim.
func TestAStatusBearingCredentialSignedByTheIssuerVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	received := signIssuedBytes(t, priv)

	var vc credential.VerifiableCredential
	if err := json.Unmarshal(received, &vc); err != nil {
		t.Fatalf("cannot parse an issued credential: %v\n%s", err, received)
	}
	rep := VerifyCredential(&vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if !rep.Verified {
		unsigned := vc
		unsigned.Proof = nil
		reMarshalled, _ := json.Marshal(unsigned)
		t.Fatalf("A VALID ISSUER SIGNATURE WAS REJECTED. The schema this module links is lossy "+
			"for an issued credential, so the bytes it re-derives are not the bytes that were "+
			"signed.\nsigned       : %s\nre-derived   : %s\nchecks: %+v",
			issuedUnsignedJSON, reMarshalled, rep.Checks)
	}
}

// TestAStatusFieldChangedAfterSigningIsRejected is the other half: without it,
// the test above is satisfied by a verifier that ignores the status member.
func TestAStatusFieldChangedAfterSigningIsRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	received := signIssuedBytes(t, priv)
	tampered := strings.Replace(string(received), `"revocationListIndex":"0"`, `"revocationListIndex":"7"`, 1)
	if tampered == string(received) {
		t.Fatal("precondition: the tamper did not apply")
	}

	var vc credential.VerifiableCredential
	if err := json.Unmarshal([]byte(tampered), &vc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if VerifyCredential(&vc, Options{ResolveIssuerKey: resolverFor(pub)}).Verified {
		t.Fatal("a credential whose revocation list index was changed after issuance VERIFIED — " +
			"the status member is not covered by the signature check")
	}
}
