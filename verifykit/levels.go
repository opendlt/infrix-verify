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

// computeProofLevel maps what this verifier proved onto the canonical proof ladder (infrix-schema assurance). Integrity (the export hash,
// the plan binding, the evidence chain, the outcome digest) is a precondition of every level, not a level. The kit reports the HIGHEST
// rung it independently witnessed:
//
//   - L4 (L0 settlement): the bundle is anchored AND its batch root is proven on Accumulate: by the embedded L0 proof chain verified against the
//     verifier's own pin (source embedded-proof, checkEmbeddedL0Proof) or by a live query of the anchor tx (source live-query).
//   - L3 (batch inclusion): the bundle hash this verifier recomputes is proven by Merkle inclusion into the batch root the anchor record
//     names (checkAnchorProof). The node-set anchorStatus field is never read for it (brief 28bd row 2, L2992).
//   - L2 (account inclusion): every claimed storage key is proven in its contract root AND that contract root is proven to be the
//     contract's leaf in the bundle's state root, the root BundleHash commits to (checkStateInclusion, brief 28bd phase 2b).
//   - L1 (storage inclusion): every claimed storage key is proven in its contract root.
//   - L0 (none): nothing above.
//
// The source of an L4 is recorded beside the level (Report.ProofLevelSource). Offline verification claims L4 only from an embedded, pinned,
// fully verified proof chain, and never from node output (operator decision 2026-11-26, L2992).
func computeProofLevel(storage, account, anchored, l0Confirmed bool) assurance.ProofLevel {
	switch {
	case anchored && l0Confirmed:
		return assurance.ProofLevelL0Settlement
	case anchored:
		return assurance.ProofLevelBatchInclusion
	case storage && account:
		return assurance.ProofLevelAccountInclusion
	case storage:
		return assurance.ProofLevelStorageInclusion
	default:
		return assurance.ProofLevelNone
	}
}

// computeGovernanceLevel classifies how strongly the operation was governed (native proof plan section 3):
//
//   - G0 (policy passed): the bundle records at least one policy decision and none of them denied.
//   - G1 (threshold approved): G0 plus `approvalsProven`: every approval's signature verified by this verifier over the package's plan hash under its
//     declared scheme (checkApprovalSignatures, brief 28bd row 1) AND every approver key proven on the key page its preimage names, at the page version it
//     signed against, with each page's threshold computed from the PROVEN page (checkApprovalKeyPages, brief 28bh). An identity string, an unsigned
//     approval, or a signature whose key is not proven on its page caps the bundle at G0.
//   - G2 (credentialed + anchored): G1 plus `governanceExecuted`: Accumulate itself executed the M-of-N approval of this plan for this bundle under the
//     relying party's governance page, its inclusion proven to a certified Directory root (checkGovernanceExecution); plus an anchored-by-proof bundle;
//     plus, when the bundle references an external or credential proof, that proof INDEPENDENTLY confirmed (an injected ExternalProofConfirmer). A node-set
//     outcome, an ExternalProofRef.Verified flag (DX P0-5b) or a recorded success is never read (NL-06).
//   - ungoverned: anything less.
func computeGovernanceLevel(bundle *evidence.EvidenceBundle, parsed, approvalsProven, governanceExecuted, externalProofConfirmed, anchored bool) assurance.GovernanceLevel {
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

	if !approvalsProven {
		return assurance.GovernanceLevelPolicyPassed
	}

	credentialsConfirmed := len(bundle.ExternalProofs) == 0 || externalProofConfirmed
	if governanceExecuted && anchored && credentialsConfirmed {
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
