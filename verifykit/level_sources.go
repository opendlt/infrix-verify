// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import "github.com/opendlt/infrix-schema/assurance"

// THE PER-LEVEL SOURCE MAP (native proof plan section 2, brief 28bj row 2): every level the report credits names where the verifier got it,
// and every source is evidence the verifier checked itself (no level rests on a field a node set). A level is listed only when THIS verifier
// witnessed it; a rung the ladder skips over (an L3 bundle that carries no state proofs has no L1 or L2) is not listed, and nothing is listed
// for a package whose integrity does not hold.
const (
	// LevelSourceRecomputed: the verifier recomputed the level from the bundle's own content (a Merkle inclusion folded to its root, a
	// content-addressed policy re-evaluated with the node's evaluator body).
	LevelSourceRecomputed = "recomputed"
	// LevelSourceEmbeddedProof: an embedded Accumulate proof the verifier checked against the pin the relying party supplied (the L0 proof
	// chain for L4, the approver keys proven on their key pages for G1, the Accumulate-executed approval for G2).
	LevelSourceEmbeddedProof = ProofSourceEmbeddedProof
	// LevelSourceLiveQuery: the verifier re-read the evidence from a live endpoint (the anchor tx from L0, an external proof from its source
	// chain).
	LevelSourceLiveQuery = ProofSourceLiveQuery
)

// levelWitness is what the verifier established on its own, the inputs of the source map.
type levelWitness struct {
	storage, account, anchored bool
	l4Source                   string // the source of an L4, empty when the bundle is not at L4
	policyAllowed              bool   // every content-addressed policy re-evaluated to allow
	approvalsProven            bool   // every approval signature verified AND its key proven on its page by an embedded key-page proof
	governanceExecuted         bool   // the approval was executed by Accumulate, proven by the embedded chain
	externalProofs             bool   // the bundle references an external proof, so G2 also rests on its live confirmation
}

// levelSources maps every credited level ("L1".."L4", "G0".."G2") to its source, from the final levels and what the verifier witnessed.
// The governance ladder is cumulative, so a credited G1 implies G0 was witnessed and a credited G2 implies G1.
func levelSources(proof assurance.ProofLevel, gov assurance.GovernanceLevel, w levelWitness) map[string]string {
	out := map[string]string{}
	if w.storage && proof >= assurance.ProofLevelStorageInclusion {
		out[assurance.ProofLevelStorageInclusion.String()] = LevelSourceRecomputed
	}
	if w.account && proof >= assurance.ProofLevelAccountInclusion {
		out[assurance.ProofLevelAccountInclusion.String()] = LevelSourceRecomputed
	}
	if w.anchored && proof >= assurance.ProofLevelBatchInclusion {
		out[assurance.ProofLevelBatchInclusion.String()] = LevelSourceRecomputed
	}
	if proof == assurance.ProofLevelL0Settlement && w.l4Source != "" {
		out[assurance.ProofLevelL0Settlement.String()] = w.l4Source
	}
	if w.policyAllowed && gov >= assurance.GovernanceLevelPolicyPassed {
		out[assurance.GovernanceLevelPolicyPassed.String()] = LevelSourceRecomputed
	}
	if w.approvalsProven && gov >= assurance.GovernanceLevelThresholdApproved {
		out[assurance.GovernanceLevelThresholdApproved.String()] = LevelSourceEmbeddedProof
	}
	if w.governanceExecuted && gov >= assurance.GovernanceLevelCredentialedAnchored {
		src := LevelSourceEmbeddedProof
		if w.externalProofs {
			src = LevelSourceLiveQuery
		}
		out[assurance.GovernanceLevelCredentialedAnchored.String()] = src
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
