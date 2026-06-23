// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package proofreceipt converts a verifykit.Report (the authoritative,
// node-free proof verdict) into the canonical proof-receipt schema
// (github.com/opendlt/infrix-schema/proofreceipt). It pairs the two published
// modules so any consumer — the CLI, the hosted playground client, an SDK — can
// turn an OFFLINE verification result into the one receipt shape without
// importing the live node. The mapping never inflates the report.
package proofreceipt

import (
	"fmt"
	"strings"

	schema "github.com/opendlt/infrix-schema/proofreceipt"
	"github.com/opendlt/infrix-verify/verifykit"
)

// VerifyConvertOptions carries the context the verifykit.Report does not hold:
// the subject, the spine artifact IDs (from the bundle), and how/where the
// verification ran (verifier/command/network). When L0 was confirmed, Network
// and Command are REQUIRED for the resulting receipt to validate.
type VerifyConvertOptions struct {
	SubjectType string // default schema.SubjectEvidence
	SubjectID   string // default = bundle/intent id from the report

	IntentID   string
	PlanID     string
	OutcomeID  string
	EvidenceID string
	AnchorTx   string

	Verifier   string // default "infrix verify"
	Command    string
	Network    string
	VerifiedAt string
	DetailsRef string
}

// FromVerifyReport converts a verifykit.Report — the authoritative independent
// proof verdict — into a canonical receipt. The mapping never inflates the
// report: witnessQuorumVerified requires a real attested witness, and L4 is
// only carried when the report confirmed an L0 anchor.
func FromVerifyReport(rep *verifykit.Report, opts VerifyConvertOptions) *schema.Receipt {
	r := schema.New()

	subjectType := opts.SubjectType
	if subjectType == "" {
		subjectType = schema.SubjectEvidence
	}
	r.Subject = schema.Subject{Type: subjectType, ID: subjectID(rep, opts)}

	if rep == nil {
		r.Status = schema.StatusFailed
		r.Summary = "Verification produced no report."
		r.Assurance.NodeTrusted = schema.BoolPtr(false)
		return r
	}

	if rep.Verified {
		r.Status = schema.StatusVerified
		r.Summary = "Verified without trusting the Infrix node."
	} else {
		r.Status = schema.StatusFailed
		r.Summary = "Verification failed."
	}

	r.Assurance = schema.Assurance{
		ProofLevel:            rep.ProofLevel,
		GovernanceLevel:       rep.GovernanceLevel,
		Label:                 rep.Tier,
		NodeTrusted:           schema.BoolPtr(rep.TrustsInfrixNode),
		L0Verified:            rep.L0Verified,
		ReplayVerified:        rep.ReplayVerified,
		WitnessQuorumVerified: rep.WitnessVerified && rep.WitnessCount > 0,
	}

	r.Artifacts = schema.Artifacts{
		IntentID:   firstNonEmpty(opts.IntentID, rep.IntentID),
		PlanID:     opts.PlanID,
		OutcomeID:  opts.OutcomeID,
		EvidenceID: firstNonEmpty(opts.EvidenceID, rep.BundleID),
		AnchorTx:   opts.AnchorTx,
	}

	r.Verification = schema.Verification{
		VerifiedAt: opts.VerifiedAt,
		Verifier:   firstNonEmpty(opts.Verifier, "infrix verify"),
		Command:    opts.Command,
		Network:    opts.Network,
	}

	// Surface skipped checks as warnings so a reader sees what was NOT done.
	for _, c := range rep.Checks {
		if c.Status == verifykit.CheckSkip {
			r.Warnings = append(r.Warnings, fmt.Sprintf("skipped: %s%s", c.Name, detailSuffix(c.Detail)))
		}
	}
	if rep.Verified && !rep.ReplayVerified {
		r.Warnings = append(r.Warnings, "deterministic replay was not reproduced")
	}

	r.DetailsRef = opts.DetailsRef
	return r
}

func subjectID(rep *verifykit.Report, opts VerifyConvertOptions) string {
	if opts.SubjectID != "" {
		return opts.SubjectID
	}
	if rep == nil {
		return ""
	}
	if opts.SubjectType == schema.SubjectIntent && rep.IntentID != "" {
		return rep.IntentID
	}
	if rep.BundleID != "" {
		return rep.BundleID
	}
	return rep.IntentID
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func detailSuffix(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return " — " + detail
}
