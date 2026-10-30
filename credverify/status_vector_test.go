// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/credential"
)

// The shared StatusList2021Entry vector: the same two literals are pinned in infrix-core
// (pkg/zkp/vc/status_vector_test.go) and infrix-schema (credential/status_vector_test.go).
const (
	statusEntryVector       = `{"id":"https://issuer.example/status/3#94567","type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"94567","statusListCredential":"https://issuer.example/status/3"}`
	legacyStatusEntryVector = `{"id":"https://issuer.example/status/3#94567","type":"StatusList2021Entry","revocationListIndex":"94567","revocationListCredential":"https://issuer.example/status/3"}`
)

// signedWithStatus signs (the legacy sha256(JSON) construction this leaf has always verified) a credential
// that carries the given status entry, so the test isolates the status check from the signature check.
func signedWithStatus(t *testing.T, entry string) (*credential.VerifiableCredential, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := `{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:1","type":["VerifiableCredential"],` +
		`"issuer":"did:web:issuer.example.com","issuanceDate":"2026-10-30T00:00:00Z","credentialSubject":{"id":"did:web:s.example.com"},` +
		`"credentialStatus":` + entry + `}`
	var vc credential.VerifiableCredential
	if err := json.Unmarshal([]byte(raw), &vc); err != nil {
		t.Fatal(err)
	}
	content, err := vc.SigningContent()
	if err != nil {
		t.Fatal(err)
	}
	vc.Proof = &credential.Proof{Type: "Ed25519Signature2020", VerificationMethod: "did:web:issuer.example.com#key-1",
		ProofPurpose: "assertionMethod", ProofValue: encodeProofValue(ed25519.Sign(priv, content))}
	return &vc, pub
}

func TestStandardStatusEntryVerifiesWithNoLegacyLabel(t *testing.T) {
	vc, pub := signedWithStatus(t, statusEntryVector)
	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if !rep.Verified {
		t.Fatalf("a StatusList2021 entry must verify: %+v", rep)
	}
	for _, l := range rep.Legacy {
		if l == string(credential.StatusFormLegacyRevocationList2020) {
			t.Fatalf("a StatusList2021 entry was labelled legacy: %v", rep.Legacy)
		}
	}
}

func TestLegacyStatusEntryIsReadUnderAnExplicitLabel(t *testing.T) {
	vc, pub := signedWithStatus(t, legacyStatusEntryVector)
	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if !rep.Verified {
		t.Fatalf("an already issued RevocationList2020-named entry stopped verifying: %+v", rep)
	}
	stated := false
	for _, l := range rep.Legacy {
		if l == string(credential.StatusFormLegacyRevocationList2020) {
			stated = true
		}
	}
	if !stated {
		t.Fatalf("the verdict must state the legacy label %q, got %v", credential.StatusFormLegacyRevocationList2020, rep.Legacy)
	}
	var detail string
	for _, ch := range rep.Checks {
		if ch.Name == "status_entry" {
			detail = ch.Detail
		}
	}
	if !strings.Contains(detail, "legacy") {
		t.Errorf("the status_entry check does not say it was read as legacy: %q", detail)
	}
}

func TestMalformedStatusEntriesAreRefused(t *testing.T) {
	for name, entry := range map[string]string{
		"both spellings":    `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"u","revocationListIndex":"1","revocationListCredential":"u"}`,
		"undefined purpose": `{"type":"StatusList2021Entry","statusPurpose":"archive","statusListIndex":"1","statusListCredential":"u"}`,
		"no list":           `{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"1"}`,
		"no status members": `{"type":"StatusList2021Entry"}`,
	} {
		vc, pub := signedWithStatus(t, entry)
		if VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)}).Verified {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s)", name)
		}
	}
}
