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
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
)

// THE SHARED BundleHash VECTOR (brief 28cd, L3124), the same two literals as infrix-schema (evidence/bundle_hash_vector_test.go) and
// infrix-core (pkg/evidence/bundle_hash_vector_test.go). This verifier (and the WASM build, the same body) recomputes BundleHash with the
// schema it pins, so a pin that drifts from the rule fails here.
const (
	bundleHashVectorJSON = `{"id":"ev-vector","type":"evidence_bundle","intentId":"intent-vector","planId":"plan-vector","outcomeId":"outcome-vector","outcomeRecordId":"outcome-vector","chain":{"intentId":"intent-vector","links":null,"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"chainHash":[12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12],"createdAt":"2026-11-26T12:00:00Z"},"stateRoot":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"anchorStatus":"unanchored","planContentHash":[14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14],"anchorCandidateDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"level":"anchored","policyDecisions":[{"timestamp":"2026-11-26T12:00:00Z","policyType":"intent:transfer","scopeKey":"acc://a.acme","decision":"allow","ruleId":"r1","auditMsg":"","blockHeight":9}],"approvalEvidence":[{"stageId":"s1","identity":"acc://a.acme","role":"approver","planHash":[11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"signedAt":"2026-11-26T12:00:00Z"}],"stepOutcomes":[{"stageId":"s1","plannedGas":1000,"actualGas":1000,"gasDrift":-0.1,"status":"success","outputHash":[13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13],"ghostStatusMatch":false,"gasConsumed":900,"gasByCategory":{"compute":250,"crypto":50,"storage":600}}],"bundleHash":[103,115,162,217,99,76,171,206,231,169,61,86,42,203,244,12,12,117,134,110,149,181,129,163,220,126,241,171,218,239,177,44],"chainVerified":false,"outcomeDigest":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],"sealedBlockHeight":4242,"state":"created","createdAt":"2026-11-26T12:00:00Z","updatedAt":"2026-11-26T12:00:00Z"}`
	bundleHashVectorHex  = "6773a2d9634cabcee7a93d562acbf40c0c75866e95b581a3dc7ef1abdaefb12c"
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
	if checkStatus(r, "cryptographic_offline") != CheckPass || checkStatus(r, "outcome_digest_binding") != CheckPass {
		t.Fatalf("the swap must pass the package gate and the outcome binding, so only the bundle hash catches it: %+v", r.Checks)
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
