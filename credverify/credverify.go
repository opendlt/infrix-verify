// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package credverify independently verifies Infrix Verifiable Credentials and
// Presentations (DX P1-4). It recomputes the signing content and checks the
// Ed25519 issuer/holder signature against a key the CALLER resolves (a DID
// resolver, a trust list) — never a key embedded in the credential, and never a
// self-asserted "verified" flag. This is the honest counterpart to the evidence
// kit's self-asserted G2 credit (P0-5b): a credential is credited only when its
// signature actually verifies here.
//
// It uses crypto/ed25519 + the stdlib + the infrix-schema contract only — no
// pairing crypto, no runtime-node dependency (the verifier isolation fence). VCs
// that need BBS+/ZK selective disclosure are proven/verified through the
// predicate path; this leaf covers signed-claim credentials (SD-JWT-style).
package credverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/opendlt/infrix-schema/credential"
)

// Check is one named verification step.
type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Report is the never-panic result of verifying a credential or presentation.
type Report struct {
	Verified bool    `json:"verified"`
	Subject  string  `json:"subject,omitempty"`
	Issuer   string  `json:"issuer,omitempty"`
	Holder   string  `json:"holder,omitempty"`
	Checks   []Check `json:"checks"`
}

// KeyResolver maps a DID + verificationMethod to its Ed25519 public key. Injected
// so the verifier trusts only keys the caller vouches for.
type KeyResolver func(did, verificationMethod string) (ed25519.PublicKey, error)

// Options configure credential verification.
type Options struct {
	// ResolveIssuerKey resolves the issuer's Ed25519 public key. Required for the
	// issuer-signature check; without it the check fails closed.
	ResolveIssuerKey KeyResolver
	// Now is the reference time for expiry (defaults to the wall clock).
	Now time.Time
	// IsRevoked reports whether a credential ID has been revoked. Optional; when
	// nil, revocation is not checked (and does not fail).
	IsRevoked func(credentialID string) bool
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

type checker struct {
	rep Report
	ok  bool
}

func newChecker() *checker { return &checker{ok: true} }

func (c *checker) add(name string, pass bool, detail string) {
	c.rep.Checks = append(c.rep.Checks, Check{Name: name, Pass: pass, Detail: detail})
	if !pass {
		c.ok = false
	}
}

// VerifyCredential independently verifies a VC's issuer signature, expiry, and
// revocation status. It never panics: any problem yields Verified=false with a
// failing Check.
func VerifyCredential(vc *credential.VerifiableCredential, opts Options) Report {
	c := newChecker()
	if vc == nil {
		c.add("structure", false, "nil credential")
		return c.rep
	}
	c.rep.Issuer = vc.Issuer
	if id, _ := vc.CredentialSubject["id"].(string); id != "" {
		c.rep.Subject = id
	}
	verifyCredentialInto(c, vc, opts)
	c.rep.Verified = c.ok
	return c.rep
}

// verifyCredentialInto runs the credential checks into an existing checker
// (shared by VerifyCredential and VerifyPresentation's embedded-VC loop).
func verifyCredentialInto(c *checker, vc *credential.VerifiableCredential, opts Options) {
	// structure
	switch {
	case vc.Issuer == "":
		c.add("structure", false, "missing issuer")
	case vc.Proof == nil || vc.Proof.ProofValue == "":
		c.add("structure", false, "missing proof")
	default:
		c.add("structure", true, "")
	}

	// issuer signature — the honest check that replaces a self-asserted flag.
	if vc.Proof != nil {
		if opts.ResolveIssuerKey == nil {
			c.add("issuer_signature", false, "no issuer key resolver supplied (fail closed)")
		} else {
			pub, err := opts.ResolveIssuerKey(vc.Issuer, vc.Proof.VerificationMethod)
			content, cerr := vc.SigningContent()
			sig, serr := hex.DecodeString(vc.Proof.ProofValue)
			switch {
			case err != nil:
				c.add("issuer_signature", false, "resolve issuer key: "+err.Error())
			case len(pub) != ed25519.PublicKeySize:
				c.add("issuer_signature", false, "issuer key is not a valid Ed25519 public key")
			case cerr != nil:
				c.add("issuer_signature", false, "signing content: "+cerr.Error())
			case serr != nil:
				c.add("issuer_signature", false, "decode proofValue: "+serr.Error())
			case !ed25519.Verify(pub, content, sig):
				c.add("issuer_signature", false, "signature does not verify against the issuer key")
			default:
				c.add("issuer_signature", true, "")
			}
		}
	}

	// expiry
	if vc.ExpirationDate != "" {
		exp, err := time.Parse(time.RFC3339, vc.ExpirationDate)
		switch {
		case err != nil:
			c.add("expiry", false, "unparseable expirationDate: "+err.Error())
		case opts.now().After(exp):
			c.add("expiry", false, "credential expired at "+vc.ExpirationDate)
		default:
			c.add("expiry", true, "")
		}
	}

	// revocation
	if opts.IsRevoked != nil && vc.ID != "" {
		if opts.IsRevoked(vc.ID) {
			c.add("revocation", false, "credential is revoked")
		} else {
			c.add("revocation", true, "")
		}
	}
}

// VerifyPresentation verifies a VP: the holder's signature over the challenge,
// and every embedded credential. It fails closed on a missing/mismatched
// challenge or an unresolved holder key.
func VerifyPresentation(vp *credential.VerifiablePresentation, challenge string, opts Options, resolveHolderKey KeyResolver) Report {
	c := newChecker()
	if vp == nil {
		c.add("structure", false, "nil presentation")
		return c.rep
	}
	c.rep.Holder = vp.Holder

	switch {
	case vp.Proof == nil || vp.Proof.ProofValue == "":
		c.add("holder_signature", false, "missing holder proof")
	case challenge != "" && vp.Proof.Challenge != challenge:
		c.add("challenge", false, "presentation challenge does not match the expected challenge")
	case resolveHolderKey == nil:
		c.add("holder_signature", false, "no holder key resolver supplied (fail closed)")
	default:
		pub, err := resolveHolderKey(vp.Holder, vp.Proof.VerificationMethod)
		content, cerr := vp.SigningContent(challenge)
		sig, serr := hex.DecodeString(vp.Proof.ProofValue)
		switch {
		case err != nil:
			c.add("holder_signature", false, "resolve holder key: "+err.Error())
		case len(pub) != ed25519.PublicKeySize:
			c.add("holder_signature", false, "holder key is not a valid Ed25519 public key")
		case cerr != nil:
			c.add("holder_signature", false, "signing content: "+cerr.Error())
		case serr != nil:
			c.add("holder_signature", false, "decode proofValue: "+serr.Error())
		case !ed25519.Verify(pub, content, sig):
			c.add("holder_signature", false, "holder signature does not verify")
		default:
			c.add("holder_signature", true, "")
		}
	}

	// every embedded credential must independently verify.
	for i := range vp.VerifiableCredential {
		vc := vp.VerifiableCredential[i]
		sub := VerifyCredential(&vc, opts)
		detail := ""
		if !sub.Verified {
			detail = firstFailure(sub)
		}
		c.add(fmt.Sprintf("credential[%d]", i), sub.Verified, detail)
	}

	c.rep.Verified = c.ok
	return c.rep
}

func firstFailure(r Report) string {
	for _, ch := range r.Checks {
		if !ch.Pass {
			return ch.Name + ": " + ch.Detail
		}
	}
	return ""
}
