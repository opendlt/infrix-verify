// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"crypto/sha256"
	"testing"

	evidence "github.com/opendlt/infrix-schema/evidence"
)

// fakeConfirmer is an injectable L0AnchorConfirmer for tests — it records
// what it was asked to confirm and returns a canned confirmation.
type fakeConfirmer struct {
	gotTx     string
	gotBundle string
	gotHash   [32]byte
	conf      *L0AnchorConfirmation
	err       error
}

func (f *fakeConfirmer) ConfirmAnchor(_ context.Context, txHash, bundleID string, bundleHash [32]byte, _ uint64) (*L0AnchorConfirmation, error) {
	f.gotTx = txHash
	f.gotBundle = bundleID
	f.gotHash = bundleHash
	return f.conf, f.err
}

// buildPortable builds a Full, anchored portable evidence package with
// policy + approval + verified external-proof evidence (i.e. a G2-capable
// bundle). anchored=false produces an unanchored Full bundle.
//
// It is built entirely from the stdlib-only infrix-schema/evidence primitives
// (the format types + the canonical portable builder), NOT the runtime
// EvidenceCollector/Exporter — so the verifier's tests depend only on the same
// schema module the verifier core does (docs/extraction-plan, M4.3), with no
// pull on the main module. Because BuildPortablePackageWithBindings and
// VerifyPortablePackage are the matched halves of one wire contract, a package
// built here verifies by construction; the tests then assert the verifier's
// classification + tamper-detection on top of it.
func buildPortable(t *testing.T, anchored bool) *evidence.PortableEvidencePackage {
	t.Helper()
	planHash := sha256.Sum256([]byte("vk-plan"))
	outcomeDigest := sha256.Sum256([]byte("vk-outcome-canonical"))

	// Hash-linked evidence chain.
	b := evidence.NewBuilder("intent-vk")
	b.AddJSON("intent", map[string]string{"id": "intent-vk"}, "")
	b.AddJSON("plan", map[string]string{"planId": "plan-vk"}, "plan-vk")
	b.AddJSON("outcome", map[string]string{"status": "success"}, "outcome-vk")
	chain := b.Build([32]byte{7})

	bundle := &evidence.EvidenceBundle{
		ID:                "bundle-vk",
		IntentID:          "intent-vk",
		PlanID:            "plan-vk",
		Level:             evidence.EvidenceLevelFull,
		Chain:             chain,
		StateRoot:         [32]byte{7},
		PolicyDecisions:   []evidence.DecisionProofRef{{PolicyType: "transfer", RuleID: "allow", Decision: "allow", BlockHeight: 1}},
		ApprovalEvidence:  []evidence.ApprovalEvidenceRef{{StageID: "s1", Identity: "acc://approver.acme", Role: "approver", PlanHash: planHash}},
		ExternalProofs:    []evidence.ExternalProofRef{{SourceChain: "acc", ProofType: "groth16", Verified: true}},
		OutcomeDigest:     outcomeDigest,
		SealedBlockHeight: 100,
	}
	if anchored {
		bundle.Anchor = evidence.AnchorStatusAnchored
		bundle.AnchorTxHash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		bundle.AnchorBlock = 4242
		bundle.AnchorRecordID = "anchor-rec-vk"
	}
	if err := bundle.Finalize(); err != nil {
		t.Fatalf("bundle.Finalize: %v", err)
	}

	bundleData, err := evidence.CanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("canonicalize bundle: %v", err)
	}

	var inclusionProofs []evidence.MerkleInclusionProof
	for i := range bundle.Chain.Links {
		if proof, perr := evidence.GenerateMerkleInclusionProof(bundle, i); perr == nil && proof != nil {
			inclusionProofs = append(inclusionProofs, *proof)
		}
	}

	in := evidence.BuildPortablePackageInputs{
		BundleData:      bundleData,
		PlanHash:        planHash,
		OutcomeDigest:   outcomeDigest,
		InclusionProofs: inclusionProofs,
		PolicyDecisions: bundle.PolicyDecisions,
	}
	if anchored {
		in.AnchorProof = &evidence.EvidenceAnchorData{
			Version:     2,
			BundleID:    bundle.ID,
			BundleHash:  bundle.BundleHash,
			ChainHash:   bundle.Chain.ChainHash,
			StateRoot:   bundle.StateRoot,
			Level:       string(bundle.Level),
			BlockHeight: bundle.AnchorBlock,
		}
		in.AnchorTxHash = bundle.AnchorTxHash
		in.AnchorBlock = bundle.AnchorBlock
	}

	pkg, err := evidence.BuildPortablePackageWithBindings(in)
	if err != nil {
		t.Fatalf("BuildPortablePackageWithBindings: %v", err)
	}
	return pkg
}

func okConfirmer() *fakeConfirmer {
	return &fakeConfirmer{conf: &L0AnchorConfirmation{Delivered: true, EntryMatches: true, BlockHeight: 4242, Detail: "ok"}}
}

func TestVerifyKitPortableBundleNoNodeTrust(t *testing.T) {
	pkg := buildPortable(t, true)
	r := Verify(context.Background(), pkg, Options{}) // no L0 confirmer

	if r.TrustsInfrixNode {
		t.Fatal("verifier must not trust the Infrix node")
	}
	if !r.Verified {
		t.Fatalf("offline verification should pass: %+v", r.Checks)
	}
	// Anchored but L0 not consulted → proof caps at L3.
	if r.ProofLevel != "L3" {
		t.Errorf("proofLevel = %q, want L3 (anchored, L0 not confirmed)", r.ProofLevel)
	}
	if !hasCheck(r, "cryptographic_offline", CheckPass) {
		t.Error("offline cryptographic gate should pass")
	}
	if !hasCheck(r, "l0_anchor", CheckSkip) {
		t.Error("l0_anchor should be skipped without an endpoint")
	}
}

func TestVerifyKitRejectsTamperedPlanHash(t *testing.T) {
	pkg := buildPortable(t, true)
	pkg.PlanHash = sha256.Sum256([]byte("tampered-plan"))
	r := Verify(context.Background(), pkg, Options{})
	if r.Verified {
		t.Fatal("tampered plan hash must not verify")
	}
	if !hasCheck(r, "plan_hash_binding", CheckFail) {
		t.Errorf("expected plan_hash_binding to fail, got %+v", r.Checks)
	}
}

func TestVerifyKitRejectsTamperedOutcomeDigest(t *testing.T) {
	pkg := buildPortable(t, true)
	pkg.OutcomeDigest = sha256.Sum256([]byte("tampered-outcome"))
	r := Verify(context.Background(), pkg, Options{})
	if r.Verified {
		t.Fatal("tampered outcome digest must not verify")
	}
	if !hasCheck(r, "outcome_digest_binding", CheckFail) {
		t.Errorf("expected outcome_digest_binding to fail, got %+v", r.Checks)
	}
}

func TestVerifyKitFetchesL0AndConfirmsAnchor(t *testing.T) {
	pkg := buildPortable(t, true)
	conf := okConfirmer()
	r := Verify(context.Background(), pkg, Options{L0Confirmer: conf})

	if conf.gotTx != pkg.AnchorTxHash {
		t.Errorf("confirmer called with tx %q, want %q", conf.gotTx, pkg.AnchorTxHash)
	}
	if conf.gotBundle != r.BundleID {
		t.Errorf("confirmer called with bundle %q, want %q", conf.gotBundle, r.BundleID)
	}
	if !hasCheck(r, "l0_anchor", CheckPass) {
		t.Fatalf("l0_anchor should pass with a confirming endpoint: %+v", r.Checks)
	}
	if r.ProofLevel != "L4" {
		t.Errorf("proofLevel = %q, want L4 (L0-confirmed anchor)", r.ProofLevel)
	}
}

// TestVerifyKitWithholdsG2FromSelfAssertedCredential proves the "no node
// trust" property (DX P0-5b): an anchored bundle whose only credential
// evidence is the self-asserted ExternalProofRef.Verified flag is classified
// at G1, NOT G2 — even when the anchor is independently confirmed (L4).
// Crediting G2 here would trust a flag the producing node wrote into the
// bundle. Independent credential verification (credverify, DX P1-4) is
// required before G2 / high_assurance can be credited.
func TestVerifyKitWithholdsG2FromSelfAssertedCredential(t *testing.T) {
	pkg := buildPortable(t, true)
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})

	if !r.Verified {
		t.Fatalf("should verify: %+v", r.Checks)
	}
	if r.ProofLevel != "L4" {
		t.Errorf("proofLevel = %q, want L4 (L0-confirmed anchor)", r.ProofLevel)
	}
	if r.GovernanceLevel != "G1" {
		t.Errorf("governanceLevel = %q, want G1 (credential proof is self-asserted, not independently verified)", r.GovernanceLevel)
	}
	if r.Tier != "L4/G1" {
		t.Errorf("tier = %q, want L4/G1", r.Tier)
	}
	if r.AssuranceClass == "high_assurance" {
		t.Errorf("assuranceClass = %q; a self-asserted credential must not reach high_assurance (DX P0-5b)", r.AssuranceClass)
	}
}

func TestVerifyKitRequireLevelFailsClosed(t *testing.T) {
	pkg := buildPortable(t, true)
	// L4/G1 is the honest achievable tier for this bundle: the anchor is
	// independently confirmable (L4), but the credential proof is self-asserted
	// so governance caps at G1 until independent credential verification lands
	// (credverify, DX P1-4 / see P0-5b).
	req, err := ParseRequiredLevel("L4/G1")
	if err != nil {
		t.Fatalf("ParseRequiredLevel: %v", err)
	}

	// No L0 confirmer → proof caps at L3 → require L4/G1 not met → fail closed.
	r := Verify(context.Background(), pkg, Options{Require: req})
	if r.Verified {
		t.Fatal("require L4/G1 must fail closed when L0 is not confirmed (proof caps at L3)")
	}
	if r.RequireMet == nil || *r.RequireMet {
		t.Errorf("RequireMet should be false, got %v", r.RequireMet)
	}

	// With L0 confirmation the same bundle reaches L4/G1 and meets it.
	r2 := Verify(context.Background(), pkg, Options{Require: req, L0Confirmer: okConfirmer()})
	if !r2.Verified || r2.RequireMet == nil || !*r2.RequireMet {
		t.Fatalf("require L4/G1 should be met with L0 confirmation: verified=%v requireMet=%v", r2.Verified, r2.RequireMet)
	}
}

func TestVerifyKitReplayUnavailableDoesNotDowngrade(t *testing.T) {
	pkg := buildPortable(t, true)
	// Replay requested but no provider → unavailable, but the crypto/L0
	// verdict must still stand.
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), Replay: true})
	if !r.Verified {
		t.Fatalf("unavailable replay must not downgrade verification: %+v", r.Checks)
	}
	if r.Replay == nil || r.Replay.Available {
		t.Fatalf("replay should be reported unavailable, got %+v", r.Replay)
	}
	if r.ProofLevel != "L4" {
		t.Errorf("proof level must not be downgraded by replay: got %q", r.ProofLevel)
	}
}

func TestVerifyKitL0ConfirmerRejectsUndelivered(t *testing.T) {
	pkg := buildPortable(t, true)
	conf := &fakeConfirmer{conf: &L0AnchorConfirmation{Delivered: false, Detail: "pending"}}
	r := Verify(context.Background(), pkg, Options{L0Confirmer: conf})
	if r.Verified {
		t.Fatal("an undelivered anchor must fail verification")
	}
	if !hasCheck(r, "l0_anchor", CheckFail) {
		t.Errorf("l0_anchor should fail for undelivered anchor: %+v", r.Checks)
	}
}

func hasCheck(r *Report, name string, status CheckStatus) bool {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status == status
		}
	}
	return false
}
