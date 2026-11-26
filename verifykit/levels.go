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
//   - L3 (batch inclusion): the bundle is anchored: the bundle hash this
//     verifier recomputes is proven by Merkle inclusion into the batch root
//     the anchor record names (checkAnchorProof). The node-set anchorStatus
//     field is never read for it (brief 28bd row 2, L2992).
//   - L0 (none): the bundle is not anchored.
//
// The source of an L4 is recorded beside the level. Today's only L4 route is
// a live L0 query; the documented rule is that offline verification can claim
// L4 only from an embedded, pinned, fully verified proof chain, and never from
// node output (operator decision 2026-11-26, L2992). Without either the kit
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
// governed:
//
//   - G0 (policy passed): the bundle records at least one policy decision
//     and none of them denied.
//   - G1 (threshold approved): G0 plus `approvalsSigned`: the bundle records
//     at least one approval and EVERY approval's signature was verified by
//     this verifier over the package's plan hash under its declared scheme
//     (checkApprovalSignatures, brief 28bd row 1). An identity string the node
//     listed is not an approval; an unsigned, forged or uncheckable approval
//     caps the bundle at G0.
//   - G2 (credentialed + anchored): G1 plus an INDEPENDENTLY confirmed
//     external/credential proof and an anchored bundle (anchored by proof, as
//     for L3). G2 is credited only when `externalProofConfirmed` is true, i.e.
//     an injected ExternalProofConfirmer re-read the proof from its source (DX
//     P1-4). It is NEVER credited from the self-asserted
//     evidence.ExternalProofRef.Verified flag (DX P0-5b).
//   - ungoverned: anything less.
func computeGovernanceLevel(bundle *evidence.EvidenceBundle, parsed, approvalsSigned, externalProofConfirmed, anchored bool) assurance.GovernanceLevel {
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

	if !approvalsSigned {
		return assurance.GovernanceLevelPolicyPassed
	}

	// G2 requires an INDEPENDENTLY confirmed external/credential proof AND an
	// anchored-by-proof bundle. With no confirmer, externalProofConfirmed is
	// false and governance caps at G1, the honest default.
	if externalProofConfirmed && anchored {
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
