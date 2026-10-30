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
	"testing"

	"github.com/opendlt/infrix-schema/credential"
)

// THE SHARED HOLDER-BINDING VECTOR (W.VP.CHALLENGE.PROOFCONFIG). These literals are identical in
// infrix-schema (credential/presentation_signing_test.go), infrix core (pkg/zkp/vc/holder_vector_test.go)
// and here: three independent implementations of one encoding. The offline verifier checks the holder
// signature over SHA-256(canonical proof configuration) || SHA-256(presentation) and refuses a
// presentation bound by concatenation.
const (
	vectorBody      = `{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5","type":["VerifiablePresentation"],"holder":"did:example:holder","verifiableCredential":[]}`
	vectorConfig    = `{"challenge":"challenge-123","created":"2026-10-27T00:00:00Z","domain":"verifier.example","nonce":"nonce-456","proofPurpose":"authentication","type":"Ed25519Signature2020","verificationMethod":"did:example:holder#key-1"}`
	vectorSigned    = "0b167e707dcad14b0c59629b8f4e9c2ebcd8ac0f9c9da1f03b501b1bd37fdc0a0419f23d2a5cf30b8491a95b486035ddc81a6a47862fe862b6189f7c75547979"
	vectorPublicKey = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	vectorSignature = "87626b45762a6173ceada98642be8884329f8f076116b3e12073cfab90c69b439140da97813574ff50e2d250a36279a50a9b1938c70aa60045ceacff88f5e60d"
)

func holderVector(t *testing.T) (*credential.VerifiablePresentation, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, err := hex.DecodeString(vectorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(vectorSignature)
	if err != nil {
		t.Fatal(err)
	}
	vp := &credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"}, ID: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Type: []string{"VerifiablePresentation"}, Holder: "did:example:holder", VerifiableCredential: []credential.VerifiableCredential{},
		Proof: &credential.Proof{Type: "Ed25519Signature2020", Created: "2026-10-27T00:00:00Z", VerificationMethod: "did:example:holder#key-1",
			ProofPurpose: "authentication", Challenge: "challenge-123", Domain: "verifier.example", Nonce: "nonce-456"},
	}
	return vp, ed25519.PublicKey(pub), sig
}

func holderResolver(pub ed25519.PublicKey) KeyResolver {
	return func(string, string) (ed25519.PublicKey, error) { return pub, nil }
}

// TestHolderVectorSigningContentAndAcceptance: the shared vector's signed bytes are reproduced here,
// and the offline verifier accepts a presentation whose proofValue is the vector signature.
func TestHolderVectorSigningContentAndAcceptance(t *testing.T) {
	vp, pub, sig := holderVector(t)
	if got := string(vp.Proof.ProofConfigurationJSON()); got != vectorConfig {
		t.Fatalf("canonical configuration = %s, want %s", got, vectorConfig)
	}
	signed, err := vp.SigningContent("challenge-123")
	if err != nil || hex.EncodeToString(signed) != vectorSigned {
		t.Fatalf("signing content = %x (%v), want %s", signed, err, vectorSigned)
	}
	vp.Proof.ProofValue = encodeProofValue(sig)
	rep := VerifyPresentation(vp, "challenge-123", Options{}, holderResolver(pub))
	for _, c := range rep.Checks {
		if c.Name == "holder_signature" && !c.Pass {
			t.Fatalf("the vector presentation must satisfy the holder check: %+v", c)
		}
	}
	if len(rep.Checks) == 0 {
		t.Fatal("no checks were run")
	}
}

func holderCheck(rep Report) (Check, bool) {
	for _, c := range rep.Checks {
		if c.Name == "holder_signature" {
			return c, true
		}
	}
	return Check{}, false
}

// TestConcatenationBoundPresentationIsRefusedOffline is the refusal twin: a holder who signed
// SHA-256(body || challenge), the binding this module used to verify, is refused by name.
func TestConcatenationBoundPresentationIsRefusedOffline(t *testing.T) {
	vp, pub, _ := holderVector(t)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("the vector key is not the seed key")
	}
	h := sha256.New()
	h.Write([]byte(vectorBody))
	h.Write([]byte("challenge-123"))
	vp.Proof.ProofValue = encodeProofValue(ed25519.Sign(priv, h.Sum(nil)))
	c, ok := holderCheck(VerifyPresentation(vp, "challenge-123", Options{}, holderResolver(pub)))
	if !ok || c.Pass {
		t.Fatalf("PLANTED DEFECT NOT REFUSED: a concatenation-bound presentation passed the holder check (%+v)", c)
	}
	if c.Detail != "holder signature does not verify" {
		t.Fatalf("refused for the wrong reason: %q", c.Detail)
	}
}

// TestEveryBoundProofMemberIsRefusedWhenChangedAfterSigning plants one change per member of the
// proof configuration into the vector presentation; each must fail the holder check.
func TestEveryBoundProofMemberIsRefusedWhenChangedAfterSigning(t *testing.T) {
	plants := map[string]func(*credential.Proof){
		"type":               func(p *credential.Proof) { p.Type = "Ed25519Signature2018" },
		"created":            func(p *credential.Proof) { p.Created = "2026-10-28T00:00:00Z" },
		"verificationMethod": func(p *credential.Proof) { p.VerificationMethod = "did:example:holder#key-2" },
		"proofPurpose":       func(p *credential.Proof) { p.ProofPurpose = "assertionMethod" },
		"domain":             func(p *credential.Proof) { p.Domain = "evil.example" },
		"nonce":              func(p *credential.Proof) { p.Nonce = "nonce-457" },
	}
	for member, plant := range plants {
		t.Run(member, func(t *testing.T) {
			vp, pub, sig := holderVector(t)
			vp.Proof.ProofValue = encodeProofValue(sig)
			plant(vp.Proof)
			c, ok := holderCheck(VerifyPresentation(vp, "challenge-123", Options{}, holderResolver(pub)))
			if !ok || c.Pass {
				t.Fatalf("PLANTED DEFECT NOT REFUSED: changing %s after signing still passed the holder check (%+v)", member, c)
			}
		})
	}
	t.Run("challenge", func(t *testing.T) {
		vp, pub, sig := holderVector(t)
		vp.Proof.ProofValue = encodeProofValue(sig)
		rep := VerifyPresentation(vp, "challenge-124", Options{}, holderResolver(pub))
		if rep.Verified {
			t.Fatal("PLANTED DEFECT NOT REFUSED: a presentation verified under a challenge it was not bound to")
		}
	})
}
