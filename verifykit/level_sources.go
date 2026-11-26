// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import "github.com/opendlt/infrix-schema/assurance"

// THE PER-LEVEL SOURCE MAP (native proof plan section 2, brief 28bj row 2): every level the report credits names where the verifier got it.
// A level is listed only when THIS verifier witnessed it; a rung the ladder skips over (an L3 bundle that carries no state proofs has no L1
// or L2) is not listed, and nothing is listed for a package whose integrity does not hold.
const (
	// LevelSourceRecomputed: the verifier recomputed the level's proof itself from the bundle's content (a Merkle inclusion folded to its
	// root, a signature checked over its signed preimage).
	LevelSourceRecomputed = "recomputed"
	// LevelSourceEmbeddedProof: an embedded proof chain verified against the verifier's own pinned network incarnation.
	LevelSourceEmbeddedProof = ProofSourceEmbeddedProof
	// LevelSourceLiveQuery: the verifier re-read the evidence from a live endpoint (the anchor tx from L0, the external proof from its
	// source chain).
	LevelSourceLiveQuery = ProofSourceLiveQuery
	// LevelSourceRecorded: the level rests on a decision the bundle records and the verifier did not re-evaluate. Today that is G0, the
	// recorded policy decisions; the verifier's own re-evaluation of the content-addressed policy set is the native proof plan's phase 6.
	// The map names it so no reader takes a recorded decision for a recomputed one.
	LevelSourceRecorded = "recorded"
)

// levelWitness is what the verifier established on its own, the inputs of the source map.
type levelWitness struct {
	storage, account, anchored bool
	l4Source                   string // the source of an L4, empty when the bundle is not at L4
	approvalsSigned            bool
	externalProofConfirmed     bool
}

// levelSources maps every credited level ("L1".."L4", "G0".."G2") to its source, from the final levels and what the verifier witnessed.
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
	if gov >= assurance.GovernanceLevelPolicyPassed {
		out[assurance.GovernanceLevelPolicyPassed.String()] = LevelSourceRecorded
	}
	if w.approvalsSigned && gov >= assurance.GovernanceLevelThresholdApproved {
		out[assurance.GovernanceLevelThresholdApproved.String()] = LevelSourceRecomputed
	}
	if w.externalProofConfirmed && gov >= assurance.GovernanceLevelCredentialedAnchored {
		out[assurance.GovernanceLevelCredentialedAnchored.String()] = LevelSourceLiveQuery
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
