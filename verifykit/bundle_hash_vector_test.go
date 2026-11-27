// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
)

// THE SHARED BundleHash VECTOR (brief 28cd, L3124), the same two literals as infrix-schema (evidence/bundle_hash_vector_test.go) and
// infrix-core (pkg/evidence/bundle_hash_vector_test.go). This verifier (and the WASM build, the same body) recomputes BundleHash with the
// schema it pins, so a pin that drifts from the rule fails here.
const (
	bundleHashVectorJSON = `{"id":"ev-vector","type":"evidence_bundle","intentId":"intent-vector","planId":"plan-vector","outcomeId":"outcome-vector","outcomeRecordId":"outcome-vector","chain":{"intentId":"intent-vector","links":null,"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"chainHash":[12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12],"createdAt":"2026-11-26T12:00:00Z"},"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"anchorStatus":"unanchored","planContentHash":[14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14],"anchorCandidateDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"level":"anchored","policyDecisions":[{"timestamp":"2026-11-26T12:00:00Z","policyType":"intent:transfer","scopeKey":"acc://a.acme","decision":"allow","ruleId":"r1","auditMsg":"","blockHeight":9}],"approvalEvidence":[{"stageId":"s1","identity":"acc://a.acme","role":"approver","planHash":[11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"signedAt":"2026-11-26T12:00:00Z"}],"stepOutcomes":[{"stageId":"s1","plannedGas":1000,"actualGas":1000,"gasDrift":-0.1,"status":"success","outputHash":[13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13],"ghostStatusMatch":false,"gasConsumed":900,"gasByCategory":{"compute":250,"crypto":50,"storage":600}}],"bundleHash":[66,205,16,14,35,33,114,106,172,61,236,254,58,64,132,226,86,87,216,223,57,174,158,196,26,107,207,159,14,126,254,150],"chainVerified":false,"bundleHashRule":2,"outcomeDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"sealedBlockHeight":4242,"state":"created","createdAt":"2026-11-26T12:00:00Z","updatedAt":"2026-11-26T12:00:00Z"}`
	bundleHashVectorHex  = "42cd100e2321726aac3decfe3a4084e25657d8df39ae9ec41a6bcf9f0e7efe96"
)

func TestTheSharedBundleHashVectorRecomputesUnderThePinnedSchema(t *testing.T) {
	var b evidence.EvidenceBundle
	if err := json.Unmarshal([]byte(bundleHashVectorJSON), &b); err != nil {
		t.Fatal(err)
	}
	if out, _ := json.Marshal(&b); string(out) != bundleHashVectorJSON {
		t.Fatalf("the vector bundle does not round-trip under the pinned schema:\nin : %s\nout: %s", bundleHashVectorJSON, out)
	}
	got, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != bundleHashVectorHex || got != b.BundleHash {
		t.Fatalf("BundleHash = %x under the pinned schema, the shared vector says %s", got, bundleHashVectorHex)
	}
}

// A bundle whose outcome digest was swapped after it was sealed (the package's digest swapped with it and the ExportHash recomputed, so the
// offline package gate and the outcome binding both pass) fails bundle_hash and proves nothing; one whose stored BundleHash was rewritten to
// match fails anchor_proof, because the anchored batch root still holds the sealed hash, and is never credited L3.
func TestASwappedOutcomeDigestFailsTheBundleHash(t *testing.T) {
	swapped := sha256.Sum256([]byte("another outcome"))
	swap := func(rehash bool) func(*evidence.EvidenceBundle, *evidence.BuildPortablePackageInputs) {
		return func(b *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) {
			b.OutcomeDigest, in.OutcomeDigest = swapped, swapped
			if rehash {
				b.BundleHash = mustBundleHash(t, b)
			}
		}
	}

	control := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, nil), Options{})
	if !control.Verified || control.ProofLevel != "L3" || checkStatus(control, "bundle_hash") != CheckPass {
		t.Fatalf("control: verified=%v %s bundle_hash=%s", control.Verified, control.ProofLevel, detail(control, "bundle_hash"))
	}

	r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, swap(false)), Options{})
	if checkStatus(r, "cryptographic_offline") != CheckPass || !strings.Contains(detail(r, "outcome_digest_binding"), "not sealed") {
		t.Fatalf("the swap must pass the package gate (the package's digest equals the bundle's), so only the bundle hash catches it, and the outcome binding names the unsealed digest: %+v", r.Checks)
	}
	if r.Verified || checkStatus(r, "bundle_hash") != CheckFail || r.ProofLevel != "L0" || r.GovernanceLevel != "ungoverned" {
		t.Fatalf("swapped outcome digest: verified=%v %s/%s bundle_hash=%s", r.Verified, r.ProofLevel, r.GovernanceLevel, detail(r, "bundle_hash"))
	}

	r = Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, swap(true)), Options{})
	if r.Verified || checkStatus(r, "bundle_hash") != CheckPass || checkStatus(r, "anchor_proof") != CheckFail || r.ProofLevel == "L3" {
		t.Fatalf("swapped outcome digest, stored hash rewritten: verified=%v %s bundle_hash=%s anchor_proof=%s",
			r.Verified, r.ProofLevel, detail(r, "bundle_hash"), detail(r, "anchor_proof"))
	}
}

// The step's per-category gas travels in the bundle and is covered: moving gas between two categories after sealing fails bundle_hash.
func TestAStepsGasCategoriesAreCoveredByTheBundleHash(t *testing.T) {
	seal := func(b *evidence.EvidenceBundle) {
		b.StepOutcomes = []evidence.StepOutcomeRef{{StageID: "s1", PlannedGas: 200000, ActualGas: 200000, GasConsumed: 2600, Status: "success",
			GasByCategory: map[string]uint64{"storage": 2000, "compute": 600}}}
	}
	control := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", seal, nil), Options{})
	if !control.Verified || checkStatus(control, "bundle_hash") != CheckPass {
		t.Fatalf("control: verified=%v bundle_hash=%s", control.Verified, detail(control, "bundle_hash"))
	}
	moved := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", seal, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.StepOutcomes[0].GasByCategory["storage"] -= 100
		b.StepOutcomes[0].GasByCategory["compute"] += 100
	}), Options{})
	if moved.Verified || checkStatus(moved, "bundle_hash") != CheckFail {
		t.Fatalf("gas moved between categories: verified=%v bundle_hash=%s", moved.Verified, detail(moved, "bundle_hash"))
	}
}

// A bundle sealed and anchored under the legacy rule (before 28cd) still verifies at its level, and the report says exactly what that rule
// leaves unsealed: OutcomeDigestSealed is false and the checks name the legacy rule. A bundle sealed under the current rule and relabelled
// legacy no longer recomputes to its stored hash and proves nothing.
func TestALegacyBundleVerifiesWithItsOutcomeDigestReportedUnsealed(t *testing.T) {
	sealedBefore := func(b *evidence.EvidenceBundle) { b.BundleHash = [32]byte{1} } // already sealed: Finalize keeps its (legacy) rule
	r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", sealedBefore, nil), Options{})
	if !r.Verified || r.ProofLevel != "L3" || r.OutcomeDigestSealed || checkStatus(r, "bundle_hash") != CheckPass ||
		!strings.Contains(detail(r, "bundle_hash"), "LEGACY") || !strings.Contains(detail(r, "outcome_digest_binding"), OutcomeNotSealed) {
		t.Fatalf("legacy bundle: verified=%v %s sealed=%v bundle_hash=%s outcome=%s", r.Verified, r.ProofLevel, r.OutcomeDigestSealed,
			detail(r, "bundle_hash"), detail(r, "outcome_digest_binding"))
	}

	current := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, nil), Options{})
	if !current.Verified || !current.OutcomeDigestSealed {
		t.Fatalf("current-rule bundle: verified=%v sealed=%v", current.Verified, current.OutcomeDigestSealed)
	}
	relabelled := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.BundleHashRule = evidence.BundleHashRuleLegacy
	}), Options{})
	if relabelled.Verified || relabelled.OutcomeDigestSealed || checkStatus(relabelled, "bundle_hash") != CheckFail || relabelled.ProofLevel != "L0" {
		t.Fatalf("relabelled legacy: verified=%v sealed=%v %s bundle_hash=%s", relabelled.Verified, relabelled.OutcomeDigestSealed, relabelled.ProofLevel, detail(relabelled, "bundle_hash"))
	}
}

// Main's condition (2026-11-26): for a bundle sealed under bundle hash rule 1 (the legacy rule) no level, receipt line or claim rests on the
// outcome digest. Such a bundle whose outcome digest was swapped (the package's with it, the ExportHash recomputed) still verifies at exactly
// the levels of the untouched bundle, the outcome binding names the unsealed outcome instead of passing, and a subsystem-attributed plan binding
// that rests on the outcome digest alone binds nothing.
func TestARule1BundlesSwappedOutcomeDigestChangesNoLevelAndIsNamedUnsealed(t *testing.T) {
	sealedBefore := func(b *evidence.EvidenceBundle) { b.BundleHash = [32]byte{1} }
	clean := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", sealedBefore, nil), Options{})
	swapped := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", sealedBefore, func(b *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) {
		b.OutcomeDigest[0] ^= 1
		in.OutcomeDigest = b.OutcomeDigest
	}), Options{})
	for name, r := range map[string]*Report{"clean": clean, "swapped": swapped} {
		if !r.Verified || r.Tier != clean.Tier || r.OutcomeDigestSealed {
			t.Fatalf("%s rule-1 bundle: verified=%v %s (clean %s) sealed=%v", name, r.Verified, r.Tier, clean.Tier, r.OutcomeDigestSealed)
		}
		if checkStatus(r, "outcome_digest_binding") == CheckPass || !strings.Contains(detail(r, "outcome_digest_binding"), OutcomeNotSealed) {
			t.Fatalf("%s rule-1 bundle: the outcome binding claimed the outcome: %s", name, detail(r, "outcome_digest_binding"))
		}
	}

	// a subsystem-attributed bundle (no approvals; the plan hash IS the outcome digest) under rule 1: the plan binding rests on the unsealed digest
	subsystem := func(b *evidence.EvidenceBundle) {
		b.BundleHash = [32]byte{1}
		b.ApprovalEvidence = nil
	}
	r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", subsystem, func(b *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) {
		in.PlanHash = b.OutcomeDigest
	}), Options{})
	if r.Verified || checkStatus(r, "plan_hash_binding") != CheckFail || !strings.Contains(detail(r, "plan_hash_binding"), OutcomeNotSealed) {
		t.Fatalf("rule-1 subsystem-attributed: verified=%v plan_hash_binding=%s", r.Verified, detail(r, "plan_hash_binding"))
	}
	// the same bundle under rule 2 binds its plan through its sealed outcome digest
	r = Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", func(b *evidence.EvidenceBundle) { b.ApprovalEvidence = nil },
		func(b *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) { in.PlanHash = b.OutcomeDigest }), Options{})
	if checkStatus(r, "plan_hash_binding") != CheckPass || !r.OutcomeDigestSealed {
		t.Fatalf("rule-2 subsystem-attributed: plan_hash_binding=%s sealed=%v", detail(r, "plan_hash_binding"), r.OutcomeDigestSealed)
	}
}
