// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/credential"
)

// The W3C CCG Ed25519Signature2020 credential vector (testdata/w3c-ed25519-signature-2020, README.txt): the
// secured credential vc_0 verifies through this module's own canonicalizer and loader, and every planted
// defect is refused.

const (
	w3cKeyHex     = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44"
	examplesSHA   = "2070ae4e75bc3b4c2cfe2b8b6e86ec45119672bbb5da283f0399ea96c60a0104"
	odrlSHA       = "bb55ab32bc6041c6ef723cbce89510128a4dfb9bec6024777240791b112c8b6c"
	examplesURL   = "https://www.w3.org/2018/credentials/examples/v1"
	odrlURL       = "https://www.w3.org/ns/odrl.jsonld"
	vectorDir     = "testdata/w3c-ed25519-signature-2020/"
	suiteContext  = "https://w3id.org/security/suites/ed25519-2020/v1"
	vectorProofV  = "z5SpZtDGGz5a89PJbQT2sgbRUiyyAGhhgjcf86aJHfYcfvPjxn6vej5na6kUzmw1jMAR9PJU9mowshQFFdGmDN14D"
	otherProofVal = "z2y3UBXAiToXLzQqeMnHiMozJ3hKxcMgLm7p8GRQA92F6JSYu49RxHQf6k1CMKnMdpj3BLRSH69b9qA9cfjE3oS7q"
)

func vectorOptions(t *testing.T) Options {
	t.Helper()
	key, _ := hex.DecodeString(w3cKeyHex)
	read := func(n string) []byte {
		b, err := os.ReadFile(vectorDir + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return Options{
		ResolveIssuerKey: func(did, vm string) (ed25519.PublicKey, error) { return ed25519.PublicKey(key), nil },
		PinnedContexts: []PinnedContext{
			{URL: examplesURL, SHA256: examplesSHA, Document: read("credentials-examples-v1.jsonld")},
			{URL: odrlURL, SHA256: odrlSHA, Document: read("odrl.jsonld")},
		},
	}
}

func vectorCredential(t *testing.T, mutate func(vc *credential.VerifiableCredential)) *credential.VerifiableCredential {
	t.Helper()
	raw, err := os.ReadFile(vectorDir + "vc_0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vc credential.VerifiableCredential
	if err := json.Unmarshal(raw, &vc); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&vc)
	}
	return &vc
}

func TestW3CEd25519Signature2020CredentialVerifiesWithTheConformingLabel(t *testing.T) {
	rep := VerifyCredential(vectorCredential(t, nil), vectorOptions(t))
	if !rep.Verified {
		t.Fatalf("the W3C vector did not verify: %+v", rep)
	}
	if rep.Construction != "Ed25519Signature2020" || len(rep.Legacy) != 0 {
		t.Fatalf("a conforming proof must report the suite and no legacy label: construction %q legacy %v", rep.Construction, rep.Legacy)
	}
}

func TestConformingProofPlantedDefectsAreRefused(t *testing.T) {
	cases := map[string]func(vc *credential.VerifiableCredential){
		"changed claim": func(vc *credential.VerifiableCredential) {
			vc.CredentialSubject["degree"].(map[string]any)["name"] = "Doctor"
		},
		"changed id":        func(vc *credential.VerifiableCredential) { vc.ID = "http://example.gov/credentials/9999" },
		"changed created":   func(vc *credential.VerifiableCredential) { vc.Proof.Created = "2019-12-11T03:50:56Z" },
		"changed purpose":   func(vc *credential.VerifiableCredential) { vc.Proof.ProofPurpose = "authentication" },
		"another signature": func(vc *credential.VerifiableCredential) { vc.Proof.ProofValue = otherProofVal },
		"base64 proofValue": func(vc *credential.VerifiableCredential) { vc.Proof.ProofValue = strings.TrimPrefix(vectorProofV, "z") },
		"carries a nonce":   func(vc *credential.VerifiableCredential) { vc.Proof.Nonce = "n" },
		"undefined member":  func(vc *credential.VerifiableCredential) { vc.CredentialSubject["unlisted"] = "x" },
		"unpinned context": func(vc *credential.VerifiableCredential) {
			vc.Context = append(vc.Context, "https://evil.example/c.jsonld")
		},
		"relative subject": func(vc *credential.VerifiableCredential) { vc.CredentialSubject["id"] = "relative" },
		"suite context out": func(vc *credential.VerifiableCredential) {
			var keep []string
			for _, c := range vc.Context {
				if c != suiteContext {
					keep = append(keep, c)
				}
			}
			vc.Context = keep
		},
	}
	for name, mutate := range cases {
		rep := VerifyCredential(vectorCredential(t, mutate), vectorOptions(t))
		if rep.Verified {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s): %+v", name, rep)
		}
	}
}

// Dropping the suite context moves a credential to the legacy reading, where a signature made over RDF is
// not a signature over sha256 of the JSON: it is refused, and it is not labelled as legacy-verified.
func TestAConformingSignatureNeverVerifiesAsTheLegacyConstruction(t *testing.T) {
	vc := vectorCredential(t, func(vc *credential.VerifiableCredential) {
		var keep []string
		for _, c := range vc.Context {
			if c != suiteContext {
				keep = append(keep, c)
			}
		}
		vc.Context = keep
	})
	rep := VerifyCredential(vc, vectorOptions(t))
	if rep.Verified || len(rep.Legacy) != 0 {
		t.Fatalf("a conforming signature verified under the legacy reading: %+v", rep)
	}
}

// A legacy-signed credential (the construction issued before the suite existed) still verifies, and the
// verdict states the legacy label instead of presenting it as the suite its proof type names.
func TestLegacyConstructionVerifiesOnlyUnderItsLabel(t *testing.T) {
	vc, pub := signedWithStatus(t, statusEntryVector)
	rep := VerifyCredential(vc, Options{ResolveIssuerKey: resolverFor(pub)})
	if !rep.Verified || rep.Construction != LegacyConstruction {
		t.Fatalf("legacy credential: %+v", rep)
	}
	found := false
	for _, l := range rep.Legacy {
		if l == LegacyConstruction {
			found = true
		}
	}
	if !found {
		t.Fatalf("the verdict does not state %s: %v", LegacyConstruction, rep.Legacy)
	}
}

// The W3C CCG presentation vector vp_0 (challenge 123, proofPurpose authentication, an embedded credential): the holder proof
// and the embedded credential verify through this module's own canonicalizer, with the conforming label and no legacy label.
func vectorPresentation(t *testing.T, mutate func(vp *credential.VerifiablePresentation)) *credential.VerifiablePresentation {
	t.Helper()
	raw, err := os.ReadFile(vectorDir + "vp_0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vp credential.VerifiablePresentation
	if err := json.Unmarshal(raw, &vp); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&vp)
	}
	return &vp
}

func TestW3CEd25519Signature2020PresentationVerifiesWithTheConformingLabel(t *testing.T) {
	opts := vectorOptions(t)
	rep := VerifyPresentation(vectorPresentation(t, nil), "123", opts, opts.ResolveIssuerKey)
	if !rep.Verified {
		t.Fatalf("the W3C presentation vector did not verify: %+v", rep)
	}
	if rep.Construction != "Ed25519Signature2020" || len(rep.Legacy) != 0 {
		t.Fatalf("a conforming holder proof must report the suite and no legacy label: %q %v", rep.Construction, rep.Legacy)
	}
}

func TestConformingHolderProofPlantedDefectsAreRefused(t *testing.T) {
	opts := vectorOptions(t)
	cases := map[string]func(vp *credential.VerifiablePresentation){
		"another challenge":  func(vp *credential.VerifiablePresentation) { vp.Proof.Challenge = "124" },
		"added domain":       func(vp *credential.VerifiablePresentation) { vp.Proof.Domain = "evil.example" },
		"added nonce":        func(vp *credential.VerifiablePresentation) { vp.Proof.Nonce = "n" },
		"changed created":    func(vp *credential.VerifiablePresentation) { vp.Proof.Created = "2021-06-04T20:50:10Z" },
		"credential purpose": func(vp *credential.VerifiablePresentation) { vp.Proof.ProofPurpose = "assertionMethod" },
		"changed holder":     func(vp *credential.VerifiablePresentation) { vp.Holder = "did:ex:other" },
		"embedded claim": func(vp *credential.VerifiablePresentation) {
			vp.VerifiableCredential[0].CredentialSubject["degree"].(map[string]any)["name"] = "Doctor"
		},
		"suite context out": func(vp *credential.VerifiablePresentation) {
			var keep []string
			for _, c := range vp.Context {
				if c != suiteContext {
					keep = append(keep, c)
				}
			}
			vp.Context = keep
		},
	}
	for name, mutate := range cases {
		if rep := VerifyPresentation(vectorPresentation(t, mutate), "", opts, opts.ResolveIssuerKey); rep.Verified {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s): %+v", name, rep)
		}
	}
	if rep := VerifyPresentation(vectorPresentation(t, nil), "other-challenge", opts, opts.ResolveIssuerKey); rep.Verified {
		t.Error("PLANTED DEFECT NOT REFUSED: a presentation replayed under another challenge verified")
	}
}

// The shared holder vector (the proof-configuration digest construction issued before presentations were signed through the
// suite) still verifies, and the verdict states the legacy holder label instead of presenting it as the suite its type names.
func TestLegacyHolderConstructionVerifiesOnlyUnderItsLabel(t *testing.T) {
	vp, pub, sig := holderVector(t)
	vp.Proof.ProofValue = encodeProofValue(sig)
	rep := VerifyPresentation(vp, "challenge-123", Options{}, holderResolver(pub))
	if !rep.Verified || rep.Construction != LegacyHolderConstruction {
		t.Fatalf("the legacy holder vector: %+v", rep)
	}
	found := false
	for _, l := range rep.Legacy {
		if l == LegacyHolderConstruction {
			found = true
		}
	}
	if !found {
		t.Fatalf("the verdict does not state %s: %v", LegacyHolderConstruction, rep.Legacy)
	}
}
