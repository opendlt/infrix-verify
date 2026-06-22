// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"github.com/opendlt/infrix-schema/assurance"
	"github.com/opendlt/infrix-schema/evidence"
)

// computeProofLevel maps the verified anchor state onto the canonical
// proof ladder. The portable bundle carries L0-settlement evidence (an
// anchored batch + the L0 tx); storage/account inclusion (L1/L2) require
// state proofs that are not part of a portable evidence package, so the
// kit reports the HIGHEST layer it can independently witness:
//
//   - L4 (L0 settlement): the bundle is anchored AND the anchor tx was
//     independently confirmed on live L0.
//   - L3 (batch inclusion): the bundle is anchored (a valid anchor proof
//     binds it to a batch) but L0 was not consulted (no endpoint).
//   - L0 (none): the bundle is not anchored.
//
// This is deliberately conservative: without a live L0 endpoint the kit
// will not claim L4 even for an anchored bundle.
func computeProofLevel(anchored, l0Confirmed bool) assurance.ProofLevel {
	switch {
	case anchored && l0Confirmed:
		return assurance.ProofLevelL0Settlement
	case anchored:
		return assurance.ProofLevelBatchInclusion
	default:
		return assurance.ProofLevelNone
	}
}

// computeGovernanceLevel classifies how strongly the operation was
// governed, read entirely from the verified bundle:
//
//   - G0 (policy passed): the bundle records at least one policy decision
//     and none of them denied.
//   - G1 (threshold approved): G0 plus signed approval evidence bound to
//     the plan hash.
//   - G2 (credentialed + anchored): G1 plus a verified external/credential
//     proof and an anchored bundle.
//   - ungoverned: anything less.
func computeGovernanceLevel(bundle *evidence.EvidenceBundle, parsed bool) assurance.GovernanceLevel {
	if !parsed {
		return assurance.GovernanceLevelUngoverned
	}

	policyAllowed := false
	for _, d := range bundle.PolicyDecisions {
		if isDeny(d.Decision) {
			// A recorded denial means the operation was not cleanly
			// governed-and-allowed; do not credit G0.
			return assurance.GovernanceLevelUngoverned
		}
		policyAllowed = true
	}
	if !policyAllowed {
		return assurance.GovernanceLevelUngoverned
	}

	hasSignedApproval := false
	for _, ae := range bundle.ApprovalEvidence {
		if ae.PlanHash != ([32]byte{}) && ae.Identity != "" {
			hasSignedApproval = true
			break
		}
	}
	if !hasSignedApproval {
		return assurance.GovernanceLevelPolicyPassed
	}

	anchored := bundle.Anchor == evidence.AnchorStatusAnchored || bundle.Anchor == evidence.AnchorStatusVerified
	hasCredentialProof := false
	for _, ep := range bundle.ExternalProofs {
		if ep.Verified {
			hasCredentialProof = true
			break
		}
	}
	if hasCredentialProof && anchored {
		return assurance.GovernanceLevelCredentialedAnchored
	}
	return assurance.GovernanceLevelThresholdApproved
}

// isDeny reports whether a policy decision string denotes a denial.
func isDeny(decision string) bool {
	switch decision {
	case "deny", "denied", "reject", "rejected", "block", "blocked":
		return true
	default:
		return false
	}
}
