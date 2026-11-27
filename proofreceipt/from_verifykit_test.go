// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package proofreceipt

import (
	"strings"
	"testing"

	schema "github.com/opendlt/infrix-schema/proofreceipt"
	"github.com/opendlt/infrix-verify/verifykit"
)

func TestFromVerifyReport_VerifiedMapsHonestly(t *testing.T) {
	rep := &verifykit.Report{
		Verified:         true,
		TrustsInfrixNode: false,
		ProofLevel:       "L4",
		GovernanceLevel:  "G2",
		Tier:             "L4/G2",
		L0Verified:       true,
		ReplayVerified:   true,
		WitnessVerified:  true,
		WitnessCount:     3,
		BundleID:         "bundle-1",
		IntentID:         "intent-1",
	}

	r := FromVerifyReport(rep, VerifyConvertOptions{Network: "kermit", Command: "infrix verify x", AnchorTx: "tx-1"})

	if r.Status != schema.StatusVerified {
		t.Fatalf("status = %q, want %q", r.Status, schema.StatusVerified)
	}
	if r.Subject.Type != schema.SubjectEvidence {
		t.Fatalf("subject type = %q, want %q", r.Subject.Type, schema.SubjectEvidence)
	}
	if r.Subject.ID != "bundle-1" {
		t.Fatalf("subject id = %q, want bundle-1", r.Subject.ID)
	}
	if r.Assurance.NodeTrusted == nil || *r.Assurance.NodeTrusted {
		t.Fatalf("nodeTrusted must be explicit false, got %v", r.Assurance.NodeTrusted)
	}
	if !r.Assurance.WitnessQuorumVerified {
		t.Fatalf("witnessQuorumVerified must be true with witnessCount=3")
	}
	if r.Assurance.ProofLevel != "L4" || r.Assurance.GovernanceLevel != "G2" {
		t.Fatalf("assurance levels = %q/%q, want L4/G2", r.Assurance.ProofLevel, r.Assurance.GovernanceLevel)
	}
	if r.Verification.Verifier != "infrix verify" {
		t.Fatalf("default verifier = %q, want infrix verify", r.Verification.Verifier)
	}
	if err := schema.Validate(r); err != nil {
		t.Fatalf("converted receipt must validate: %v", err)
	}
}

func TestFromVerifyReport_NilReportFailsClosed(t *testing.T) {
	r := FromVerifyReport(nil, VerifyConvertOptions{})
	if r.Status != schema.StatusFailed {
		t.Fatalf("nil report status = %q, want failed", r.Status)
	}
	if r.Assurance.NodeTrusted == nil || *r.Assurance.NodeTrusted {
		t.Fatalf("nil report must assert nodeTrusted=false explicitly")
	}
}

func TestFromVerifyReport_NoQuorumWithoutWitness(t *testing.T) {
	rep := &verifykit.Report{Verified: true, WitnessVerified: true, WitnessCount: 0, BundleID: "b"}
	r := FromVerifyReport(rep, VerifyConvertOptions{})
	if r.Assurance.WitnessQuorumVerified {
		t.Fatalf("witnessQuorumVerified must be false when witnessCount=0")
	}
}

// A verified bundle sealed under bundle hash rule 1 proves no outcome: its receipt names no outcome and says so (main's condition, brief 28cd).
func TestFromVerifyReport_ARule1BundlesReceiptClaimsNoOutcome(t *testing.T) {
	rep := &verifykit.Report{Verified: true, ProofLevel: "L3", GovernanceLevel: "G0", Tier: "L3/G0", BundleID: "bundle-1", OutcomeDigestSealed: false}
	r := FromVerifyReport(rep, VerifyConvertOptions{OutcomeID: "outcome-1"})
	if r.Artifacts.OutcomeID != "" {
		t.Fatalf("the receipt claims outcome %q of a rule-1 bundle", r.Artifacts.OutcomeID)
	}
	found := false
	for _, w := range r.Warnings {
		if strings.Contains(w, verifykit.OutcomeNotSealed) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the receipt does not say the outcome is unsealed: %v", r.Warnings)
	}
	if err := schema.Validate(r); err != nil {
		t.Fatalf("receipt must validate: %v", err)
	}
	sealed := FromVerifyReport(&verifykit.Report{Verified: true, ProofLevel: "L3", GovernanceLevel: "G0", Tier: "L3/G0", BundleID: "bundle-1", OutcomeDigestSealed: true},
		VerifyConvertOptions{OutcomeID: "outcome-1"})
	if sealed.Artifacts.OutcomeID != "outcome-1" {
		t.Fatalf("a sealed outcome lost its id: %q", sealed.Artifacts.OutcomeID)
	}
}
