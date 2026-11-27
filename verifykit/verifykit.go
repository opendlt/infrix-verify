// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package verifykit is the independent verifier/replay kit
// (platform-review-2 Epic B). It verifies an exported Infrix portable
// evidence package WITHOUT trusting the Infrix node that produced it:
// it recomputes every cryptographic binding offline, fetches the
// Accumulate L0 anchor directly from an operator-supplied endpoint, and
// classifies the achieved assurance (proof level L0–L4, governance level
// ungoverned/G0–G2, IU assurance class).
//
// A third party can run `infrix verify ./bundle.infrix.json --l0 <url>`
// from a clean machine with only the bundle and an L0 endpoint and get a
// trustless verdict.
package verifykit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opendlt/infrix-schema/assurance"
	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/stateroot"
	"github.com/opendlt/infrix-verify/witness"
)

// The sources an L4 proof level can come from (Report.ProofLevelSource).
const (
	ProofSourceLiveQuery     = "live-query"
	ProofSourceEmbeddedProof = "embedded-proof"
)

// The bindings governance can rest on (Report.GovernanceBinding).
const (
	GovernanceBindingVersion  = "version-bound (off-chain)"
	GovernanceBindingExecuted = "accumulate-executed"
)

// CheckStatus is the per-check outcome.
type CheckStatus string

const (
	// CheckPass means the check verified.
	CheckPass CheckStatus = "pass"
	// CheckFail means the check failed — verification is not trustworthy.
	CheckFail CheckStatus = "fail"
	// CheckSkip means the check was not applicable / not requested (e.g.
	// L0 confirmation without an endpoint). A skip never marks the
	// package verified=false, but it caps the achievable proof level.
	CheckSkip CheckStatus = "skip"
)

// Check is one named verification step.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
	// Public carries the public identifiers a check verified, each in full under its labelled key and in its exact format; the Detail prose
	// names them by an identifying prefix only (brief 28bs row 1, main's ruling on the agent key scan: a relying party compares the full
	// values from these keys, and a rendered report carries no unlabelled 32-byte hex run). Nil when the check names none.
	Public *PublicRefs `json:"public,omitempty"`
}

// PublicRefs are the public identifiers an embedded-proof check verified. Each is the full value in one exact format:
//   - TxHash: the Accumulate transaction hash, 64 lowercase hex characters;
//   - BatchRoot: the anchor batch root the transaction wrote, 64 lowercase hex characters;
//   - DirectoryRoot: the certified Directory BPT root the proof chain reached, 64 lowercase hex characters;
//   - PinID: the pin the verdict is relative to, "pin:" then 64 lowercase hex characters.
type PublicRefs struct {
	TxHash        string `json:"txHash,omitempty"`
	BatchRoot     string `json:"batchRoot,omitempty"`
	DirectoryRoot string `json:"directoryRoot,omitempty"`
	PinID         string `json:"pinId,omitempty"`
}

// shortHex names a public value in report prose by its identifying prefix (16 hex characters); the full value is in the check's Public.
func shortHex(b []byte) string {
	const keep = 8
	if len(b) <= keep {
		return fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("%x...", b[:keep])
}

// ReplayResult is the optional deterministic-replay outcome. Replay is
// stricter than verify and requires replay material; when material is
// absent the verifier reports availability=false and does NOT downgrade
// the cryptographic / L0 verdict.
type ReplayResult struct {
	Available bool   `json:"available"`
	Matched   bool   `json:"matched,omitempty"`
	Detail    string `json:"detail"`
}

// Report is the machine-readable verdict.
type Report struct {
	// Verified is true iff every applicable check passed AND (when a
	// required level was requested) the achieved levels meet it.
	Verified bool `json:"verified"`
	// TrustsInfrixNode is always false — the kit verifies cryptographically
	// and fetches L0 directly.
	TrustsInfrixNode bool `json:"trustsInfrixNode"`

	ProofLevel          string  `json:"proofLevel"`
	GovernanceLevel     string  `json:"governanceLevel"`
	AssuranceClass      string  `json:"assuranceClass"`
	AssuranceMultiplier float64 `json:"assuranceMultiplier"`
	Tier                string  `json:"tier"`
	// ProofLevelSource records where an L4 came from: ProofSourceLiveQuery (the anchor tx re-read from an L0 endpoint) or
	// ProofSourceEmbeddedProof (an embedded proof chain verified against the verifier's own pinned network incarnation). Empty below
	// L4. Operator decision 2026-11-26 (L2992): offline verification may claim L4 only from an embedded, pinned, fully verified proof
	// chain, never from node output.
	ProofLevelSource string `json:"proofLevelSource,omitempty"`
	// LevelSources names, for EVERY level the report credits ("L1".."L4", "G0".."G2"), where the verifier got it: LevelSourceRecomputed,
	// LevelSourceEmbeddedProof or LevelSourceLiveQuery, never a field the node set (native proof plan section 2, brief 28bj row 2). A level
	// the verifier did not witness is not listed; nil when nothing is credited.
	LevelSources map[string]string `json:"levelSources,omitempty"`
	// EmbeddedTrustRoot names the pin every embedded-proof level (L4, G1, G2 sourced embedded-proof) was verified against: the pin's network
	// and ID, and whether the relying party supplied it (brief 28bl row 1). A level verified under a local run's pin is relative to that
	// run's own network ("local-embedded"), never Kermit, and a surface must say so. Nil when no level is sourced embedded-proof.
	EmbeddedTrustRoot *TrustRoot `json:"embeddedTrustRoot,omitempty"`
	// Clock reports the relying party's clock over the embedded proofs (brief 28bs row 6 (d)): whether it was applied, the time it read, and
	// the trusting period and drift bound it enforced. Nil when no level is sourced embedded-proof; Applied false when one is but no clock was
	// passed (the verdict is clock-unchecked).
	Clock *ClockReport `json:"clock,omitempty"`
	// GovernanceBinding records how the approvals behind G1 or G2 are bound to the key page (empty below G1):
	//   - GovernanceBindingVersion ("version-bound (off-chain)") at G1: each approval's key is proven on its page at EXACTLY the page version its
	//     signature claims. That proves "a key that was on the page at version V signed"; it cannot exclude a key removed later signing while
	//     claiming the old version (backdating).
	//   - GovernanceBindingExecuted ("accumulate-executed") at G2: Accumulate executed the approval under its own sequence and version rules at a
	//     proven block, which excludes backdating; that is why G2 is the higher level (main ruling 2026-11-26).
	GovernanceBinding string `json:"governanceBinding,omitempty"`

	// OutcomeDigestSealed reports that the bundle's outcome digest (with its anchor candidate digest, plan content hash and sealed block
	// height) is covered by the BundleHash this verifier recomputed and held to the stored one (brief 28cd, L3124). False for a bundle
	// sealed under the legacy hash rule, whose outcome digest is bound to the package but not sealed into the bundle's hash: only a matching
	// replay proves such a bundle's outcome.
	OutcomeDigestSealed bool `json:"outcomeDigestSealed"`

	// legacyHashRule is set when the bundle recomputed under the legacy rule (checkBundleHash).
	legacyHashRule bool

	// platform-review-3 Epic 2: the layered verification truth, identical
	// to the fields the Nexus proof inspector surfaces. CryptographicallyVerified
	// is the offline binding gate; L0Verified is the live anchor
	// confirmation; ReplayAvailable/ReplayVerified report deterministic
	// replay; SemanticVerified means the operation re-executed to the same
	// outcome; FullyVerified requires crypto + (L0 when anchored) + replay.
	CryptographicallyVerified bool `json:"cryptographicallyVerified"`
	L0Verified                bool `json:"l0Verified"`
	ReplayAvailable           bool `json:"replayAvailable"`
	ReplayVerified            bool `json:"replayVerified"`
	SemanticVerified          bool `json:"semanticVerified"`
	FullyVerified             bool `json:"fullyVerified"`

	// platform-review-3 Epic 5: independent witness network. WitnessCount
	// is the number of distinct valid witnesses; WitnessThresholdMet is
	// true when that count meets the required threshold; WitnessVerified
	// is true when at least one valid witness attested; and
	// IndependentReplayVerified is true when an independent witness (not
	// this verifier) reproduced the outcome.
	WitnessVerified           bool `json:"witnessVerified"`
	WitnessThresholdMet       bool `json:"witnessThresholdMet"`
	WitnessCount              int  `json:"witnessCount"`
	IndependentReplayVerified bool `json:"independentReplayVerified"`
	// WitnessOperatorCount is the number of DISTINCT independent operators the
	// valid witnesses span (independence, not just distinct keys);
	// WitnessOperatorThresholdMet is true when it meets RequireWitnessOperators.
	WitnessOperatorCount        int  `json:"witnessOperatorCount"`
	WitnessOperatorThresholdMet bool `json:"witnessOperatorThresholdMet"`

	// PolicyReevaluations records each content-addressed policy this verifier re-ran for G0 (brief 28bi): its recomputed hash, what the
	// verifier's own evaluation decided, and whether the relying party pinned it.
	PolicyReevaluations []PolicyReevaluation `json:"policyReevaluations,omitempty"`

	Checks []Check       `json:"checks"`
	Replay *ReplayResult `json:"replay,omitempty"`

	// RequireMet is set only when a RequiredLevel was supplied: true iff
	// the achieved proof+governance levels meet the requirement.
	RequireMet *bool `json:"requireMet,omitempty"`

	// BundleID / IntentID echo the verified bundle's identity.
	BundleID string `json:"bundleId,omitempty"`
	IntentID string `json:"intentId,omitempty"`
}

// RequiredLevel expresses a minimum (proof, governance) the caller
// demands. Verify fails closed when the achieved levels are below it.
type RequiredLevel struct {
	Proof      assurance.ProofLevel
	Governance assurance.GovernanceLevel
	Raw        string
}

// ParseRequiredLevel parses an "L<n>/G<n>" string (e.g. "L4/G2").
func ParseRequiredLevel(s string) (*RequiredLevel, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("verifykit: --require must be L<n>/G<n> (e.g. L4/G2), got %q", s)
	}
	proof, err := parseProofLevel(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}
	gov, err := parseGovernanceLevel(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}
	return &RequiredLevel{Proof: proof, Governance: gov, Raw: s}, nil
}

func parseProofLevel(s string) (assurance.ProofLevel, error) {
	for _, p := range assurance.ValidProofLevels() {
		if strings.EqualFold(p.String(), s) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("verifykit: unknown proof level %q (one of L0..L4)", s)
}

func parseGovernanceLevel(s string) (assurance.GovernanceLevel, error) {
	for _, g := range assurance.ValidGovernanceLevels() {
		if strings.EqualFold(g.String(), s) {
			return g, nil
		}
	}
	return 0, fmt.Errorf("verifykit: unknown governance level %q (one of ungoverned/G0/G1/G2)", s)
}

// Options configure a verification run.
type Options struct {
	// L0Confirmer, when non-nil, performs the live L0 anchor
	// confirmation (step 10-11). Nil means no L0 endpoint was supplied:
	// the l0_anchor check is skipped and the proof level caps at L3
	// (batch inclusion) for anchored bundles.
	L0Confirmer L0AnchorConfirmer

	// ExternalProofConfirmer, when non-nil, independently re-reads a bundle's
	// external/credential proof reference from its source chain. Governance level
	// G2 (credentialed + anchored) is credited ONLY when this confirms — never
	// from the self-asserted ExternalProofRef.Verified flag (DX P0-5b/P1-4). Nil
	// means external proofs are not independently confirmed and governance caps
	// at G1.
	ExternalProofConfirmer ExternalProofConfirmer

	// PinnedPolicies is the relying party's policy registry: policy type -> the content hash it accepts (brief 28bi). When non-nil, every
	// re-evaluated policy of a pinned type must have the pinned hash (else the policy_reevaluation check fails) and every pinned type must be
	// present (else G0 is not credited). Nil means no registry is pinned: the re-evaluated hashes are reported for the relying party.
	PinnedPolicies map[string][32]byte

	// Require, when non-nil, gates Verified on the achieved levels.
	Require *RequiredLevel

	// Replay enables deterministic replay (stricter than verify). When
	// ReplayProvider is nil, replay is reported unavailable without
	// downgrading the cryptographic verdict.
	Replay         bool
	ReplayProvider ReplayProvider

	// RequireReplay fails verification closed unless deterministic replay
	// is available AND reproduces the recorded outcome. platform-review-3
	// Epic 2: public-production bundles require replay by default. When
	// false, an unavailable replay is reported but does not downgrade the
	// cryptographic / L0 verdict (legacy behaviour).
	RequireReplay bool

	// RequireWitnessThreshold fails verification closed unless at least
	// this many DISTINCT valid witnesses attested the bundle reproduces.
	// 0 means witness receipts are evaluated and reported but not
	// required. platform-review-3 Epic 5.
	RequireWitnessThreshold int

	// WitnessKeyPageAuthorizer, when non-nil, makes witness counting require
	// live L0 key-page authorization: each receipt's signing key must be a
	// current, authorized key on the witness's declared key page (not merely
	// a held Ed25519 key). Receipts that fail authorization — or whose key
	// was revoked — do not count. A lookup error is fail-closed.
	WitnessKeyPageAuthorizer witness.KeyPageAuthorizer

	// WitnessNowUnix / WitnessReceiptMaxAgeSeconds enable receipt freshness.
	// When MaxAge > 0 (and NowUnix > 0) a witness receipt older than MaxAge
	// is rejected as stale; a future-dated receipt is always rejected when
	// NowUnix > 0. 0 disables freshness (archived proofs verify forever).
	WitnessNowUnix              int64
	WitnessReceiptMaxAgeSeconds int64

	// WitnessOperators maps each witness identity to the independent operator
	// (organisation) that runs it — from an external witness registry. It lets
	// the verifier judge independence by DISTINCT OPERATORS, not distinct keys.
	WitnessOperators map[string]string
	// RequireRegisteredWitnesses counts only witnesses present in
	// WitnessOperators (approved independent operators); ad-hoc witnesses are
	// rejected.
	RequireRegisteredWitnesses bool
	// RequireWitnessOperators fails verification closed unless the valid
	// witnesses span at least this many DISTINCT independent operators.
	RequireWitnessOperators int

	// StateRootProof is the document an export attached beside the package under stateroot.DocumentKey: an inclusion proof of the bundle's state root into a
	// root-history seal the node anchored (package stateroot). The application reads it from the exported file (verifykit parses no files); nil means none was
	// attached, and the state_root_accumulator check is then a SKIP that leaves every verdict exactly as it was (every bundle exported before the node kept a root
	// history). StateRootProofError, when non-empty, says a document was attached that did not decode: the check then FAILS with that text.
	StateRootProof      *stateroot.Document
	StateRootProofError string
	// StateRootAnchors reads an L0 anchor entry, its listed roots and its canonical window (the verifier's port, like L0Confirmer). Nil means no L0 endpoint was supplied: a consistent
	// proof is then a SKIP, exactly as l0_anchor is, because that the node anchored the seal is not independently confirmed.
	StateRootAnchors stateroot.AnchorReader
	// L0Network names the network whose COMPILED pin the embedded Accumulate proofs (l0Proof, keyPageProofs, governanceExecution) are verified against;
	// empty means Kermit, the only network with a compiled pin. L0Pin, when non-nil, is an explicit relying-party pin used instead (a devnet's in-process
	// simulator pin, an earlier Kermit incarnation); the report names it. Neither is ever read from the bundle (native proof plan PN-01).
	L0Network string
	L0Pin     *consensus.Pin
	// Clock is the relying party's own clock (brief 28bs row 6 (d), L3008 (d)). When set, every embedded Accumulate proof (the anchor chain,
	// the key-page proofs, the governance execution and the external-proof chains) is held to CometBFT's trusting-period and clock-drift
	// checks against it, and the report records that it was applied (Report.Clock). Nil means no clock: those checks are not made and the
	// report says the verdict is clock-unchecked. `infrix verify` passes the system time.
	Clock *l0proof.RelyingPartyClock
	// GovernanceAccount and GovernancePage are the app's governance data account and key page, named by the RELYING PARTY. G2 is credited only from an
	// Accumulate-executed approval under exactly this page to exactly this account; with either empty, governance caps at G1.
	GovernanceAccount string
	GovernancePage    string

	// RequireStateRootProof turns a SKIP (no document, awaiting the next anchor, no endpoint) into a failure, for a verifier that accepts only a bundle whose state
	// root is proven against L0.
	RequireStateRootProof bool
}

// Verify runs the full verification pipeline against a portable evidence
// package and returns a machine-readable Report. It never panics and
// never returns an error — every failure is captured as a failed Check
// so the report is always renderable.
func Verify(ctx context.Context, pkg *evidence.PortableEvidencePackage, opts Options) *Report {
	report := &Report{TrustsInfrixNode: false}

	if pkg == nil {
		report.Checks = append(report.Checks, Check{Name: "package_present", Status: CheckFail, Detail: "nil package"})
		report.finalizeLevels(assurance.ProofLevelNone, assurance.GovernanceLevelUngoverned, opts.Require)
		return report
	}

	// Parse the embedded bundle once for the independent re-derivations.
	var bundle evidence.EvidenceBundle
	bundleParsed := json.Unmarshal(pkg.BundleData, &bundle) == nil && len(pkg.BundleData) > 0
	if bundleParsed {
		report.BundleID = bundle.ID
		report.IntentID = bundle.IntentID
	}

	// 1. Authoritative offline cryptographic gate. VerifyPortablePackage
	//    checks canonical encoding, export-hash integrity, bundle parse,
	//    plan-hash binding, outcome-digest binding, inclusion proofs,
	//    anchor cross-binding, trust-snapshot binding, policy-decision
	//    digest, and plugin-version structure — all offline, fail-loud.
	if err := evidence.VerifyPortablePackage(pkg); err != nil {
		report.add("cryptographic_offline", CheckFail, err.Error())
	} else {
		report.add("cryptographic_offline", CheckPass, "all offline bindings verified")
	}

	// 2-8. Independent, individually-attributable re-derivations so the
	//      report localises any tamper to a named binding.
	if !bundleParsed {
		report.add("bundle_parse", CheckFail, "BundleData is empty or not a valid EvidenceBundle")
	} else {
		report.add("bundle_parse", CheckPass, "bundle "+bundle.ID)
	}

	report.checkBundleHash(&bundle, bundleParsed)
	report.checkPlanHashBinding(pkg, &bundle, bundleParsed)
	report.checkOutcomeDigestBinding(pkg, &bundle, bundleParsed)
	report.checkEvidenceChain(pkg)
	report.checkPluginInventory(pkg)

	// G1 is credited from approvals whose signatures this verifier checks itself (brief 28bd row 1), never from an identity string.
	approvalsSigned := report.checkApprovalSignatures(pkg, &bundle, bundleParsed)

	// G0 is credited from this verifier's own re-evaluation of the bundle's content-addressed policies, never from a recorded decision
	// (brief 28bi, native proof plan phase 6).
	policyAllowed := report.checkPolicyReevaluation(&bundle, bundleParsed, opts.PinnedPolicies, pkg.PlanHash, opts)

	// "Anchored" is the Merkle inclusion of the bundle hash THIS verifier recomputes into the batch root the anchor record names
	// (brief 28bd row 2). The node-set anchorStatus field is never read for it.
	anchored := report.checkAnchorProof(pkg, &bundle, bundleParsed)

	// L1/L2: the claimed keys in their contract roots and the contract roots in the bundle's state root, recomputed (brief 28bd phase 2b).
	stateProven := report.checkStateInclusion(&bundle, bundleParsed)

	// 9-11. Live L0 confirmation — fetch the anchor tx directly from L0.
	l0Confirmed := report.checkL0Anchor(ctx, &bundle, anchored, opts.L0Confirmer)
	externalProofConfirmed, externalEmbedded := report.checkExternalProof(ctx, &bundle, opts)

	// The embedded Accumulate proofs, each against the verifier's own pin (native proof plan phases 5 and 7): offline L4, the approver keys on their
	// pages (G1) and the Accumulate-executed approval (G2).
	l0Embedded := report.checkEmbeddedL0Proof(&bundle, bundleParsed, anchored, opts)
	keyPagesProven := report.checkApprovalKeyPages(&bundle, approvalsSigned, opts)
	governanceExecuted := report.checkGovernanceExecution(&bundle, pkg.PlanHash, bundleParsed, opts)

	// The bundle's state root against the node's anchored root history. It changes no level (the ladder has no state-root rung); a FAIL is a failure of the
	// bundle, and so of the cryptographic verdict below.
	if bundleParsed {
		report.checkStateRootProof(ctx, &bundle, opts)
	}

	// crypto verdict = every check so far passed (these are all the
	// offline cryptographic + structural bindings; L0 is separate).
	report.CryptographicallyVerified = !report.hasFailuresExcept("l0_anchor")

	// 15. Deterministic replay. Runs before finalize so a required-but-
	//     unavailable replay (or a replay that produced a divergent
	//     outcome) is counted as a failure in the overall verdict.
	if opts.Replay || opts.RequireReplay {
		report.Replay = runReplay(ctx, pkg, &bundle, opts.ReplayProvider)
		report.applyReplayChecks(opts.RequireReplay)
	}

	// 16. Independent witness receipts (platform-review-3 Epic 5 + hardening).
	report.evaluateWitnesses(pkg, &bundle, anchored, witnessGate{
		authorizer:        opts.WitnessKeyPageAuthorizer,
		nowUnix:           opts.WitnessNowUnix,
		maxAgeSeconds:     opts.WitnessReceiptMaxAgeSeconds,
		requireThreshold:  opts.RequireWitnessThreshold,
		operators:         opts.WitnessOperators,
		requireRegistered: opts.RequireRegisteredWitnesses,
		requireOperators:  opts.RequireWitnessOperators,
	})

	// 12-14. Classify achieved assurance + finalize the verdict.
	proof := computeProofLevel(stateProven.Storage, stateProven.Account, anchored, l0Confirmed || l0Embedded)
	gov := computeGovernanceLevel(&bundle, bundleParsed, policyAllowed, approvalsSigned && keyPagesProven, governanceExecuted, externalProofConfirmed, anchored)
	// Integrity is a precondition of every level, not a level (native proof plan PV-INT-01): a package whose export hash, plan binding,
	// evidence chain or outcome digest does not recompute proves nothing, whatever else it carries.
	if !report.integrityHolds() {
		proof, gov = assurance.ProofLevelNone, assurance.GovernanceLevelUngoverned
		report.OutcomeDigestSealed = false
	}
	report.finalizeLevels(proof, gov, opts.Require)
	switch gov {
	case assurance.GovernanceLevelThresholdApproved:
		report.GovernanceBinding = GovernanceBindingVersion
	case assurance.GovernanceLevelCredentialedAnchored:
		report.GovernanceBinding = GovernanceBindingExecuted
	}
	if proof == assurance.ProofLevelL0Settlement {
		// an embedded, pinned, fully verified chain is the offline source; a live query alone is the other
		if l0Embedded {
			report.ProofLevelSource = ProofSourceEmbeddedProof
		} else {
			report.ProofLevelSource = ProofSourceLiveQuery
		}
	}
	report.LevelSources = levelSources(proof, gov, levelWitness{
		storage: stateProven.Storage, account: stateProven.Account, anchored: anchored, l4Source: report.ProofLevelSource,
		policyAllowed: policyAllowed, approvalsProven: approvalsSigned && keyPagesProven, governanceExecuted: governanceExecuted,
		externalProofs: len(bundle.ExternalProofs) > 0, externalEmbedded: externalEmbedded,
	})
	for _, src := range report.LevelSources {
		if src == LevelSourceEmbeddedProof {
			report.EmbeddedTrustRoot = trustRootOf(opts)
			break
		}
	}

	// Derived layered-verification flags (mirror the Nexus inspector).
	report.L0Verified = l0Confirmed || l0Embedded
	report.ReplayAvailable = report.Replay != nil && report.Replay.Available
	report.ReplayVerified = report.Replay != nil && report.Replay.Available && report.Replay.Matched
	report.SemanticVerified = report.ReplayVerified
	report.FullyVerified = report.CryptographicallyVerified && report.ReplayVerified
	if anchored {
		report.FullyVerified = report.FullyVerified && report.L0Verified
	}

	return report
}

// applyReplayChecks turns the replay result into pass/fail/skip checks.
// A replay that ran and produced a divergent outcome is always a
// failure. An unavailable replay fails only when requireReplay is set;
// otherwise it is a skip that does not downgrade the verdict (legacy
// behaviour for bundles without replay material).
func (r *Report) applyReplayChecks(requireReplay bool) {
	res := r.Replay
	switch {
	case res == nil:
		if requireReplay {
			r.add("replay_required", CheckFail, "deterministic replay required but not attempted")
		}
	case res.Available && res.Matched:
		r.add("replay", CheckPass, res.Detail)
	case res.Available && !res.Matched:
		// Replay ran and the operation did NOT reproduce — a genuine
		// semantic failure regardless of whether replay was required.
		r.add("replay", CheckFail, res.Detail)
	default: // unavailable
		if requireReplay {
			r.add("replay_required", CheckFail, res.Detail)
		} else {
			r.add("replay", CheckSkip, res.Detail)
		}
	}
}

// integrityChecks are the bindings every level presupposes.
var integrityChecks = []string{"cryptographic_offline", "bundle_parse", "bundle_hash", "plan_hash_binding", "outcome_digest_binding", "evidence_chain"}

// integrityHolds reports whether every integrity check ran and passed. The one exception is outcome_digest_binding of a bundle sealed under the
// legacy rule: it is SKIPPED, naming OutcomeNotSealed, because that rule's BundleHash does not cover the outcome digest, so the bundle's levels
// rest on what its hash does cover and nothing rests on the outcome (brief 28cd, L3124, main's condition).
func (r *Report) integrityHolds() bool {
	for _, name := range integrityChecks {
		passed := false
		for _, c := range r.Checks {
			if c.Name == name {
				if name == "outcome_digest_binding" && c.Status == CheckSkip && r.legacyHashRule {
					passed = true
					continue
				}
				if c.Status != CheckPass {
					return false
				}
				passed = true
			}
		}
		if !passed {
			return false
		}
	}
	return true
}

// add appends a check.
func (r *Report) add(name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// addPublic records a check together with the public identifiers it verified (brief 28bs row 1).
func (r *Report) addPublic(name string, status CheckStatus, detail string, public *PublicRefs) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail, Public: public})
}

// hasFailures reports whether any check failed.
func (r *Report) hasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return true
		}
	}
	return false
}

// hasFailuresExcept reports whether any check other than the named ones
// failed. Used to compute CryptographicallyVerified (every binding
// except the live-L0 confirmation).
func (r *Report) hasFailuresExcept(except ...string) bool {
	skip := make(map[string]struct{}, len(except))
	for _, n := range except {
		skip[n] = struct{}{}
	}
	for _, c := range r.Checks {
		if c.Status != CheckFail {
			continue
		}
		if _, ok := skip[c.Name]; ok {
			continue
		}
		return true
	}
	return false
}

func (r *Report) checkPlanHashBinding(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, ok bool) {
	if !ok {
		r.add("plan_hash_binding", CheckFail, "bundle did not parse")
		return
	}
	if pkg.PlanHash == ([32]byte{}) {
		r.add("plan_hash_binding", CheckFail, "PlanHash is zero")
		return
	}
	var nonZero int
	for _, ae := range bundle.ApprovalEvidence {
		if ae.PlanHash == ([32]byte{}) {
			continue
		}
		nonZero++
		if ae.PlanHash == pkg.PlanHash {
			r.add("plan_hash_binding", CheckPass, "matches a signed approval plan hash")
			return
		}
	}
	if nonZero > 0 {
		r.add("plan_hash_binding", CheckFail, "PlanHash matches no signed approval plan hash")
		return
	}
	// Subsystem-attributed fallback: PlanHash may equal OutcomeDigest. It rests on the outcome digest alone, so it binds nothing for a bundle whose
	// BundleHash does not cover that digest (the legacy rule; brief 28cd, L3124, main's condition).
	if pkg.PlanHash == pkg.OutcomeDigest {
		if !bundle.BundleHashCoversSealedDigests() {
			r.add("plan_hash_binding", CheckFail, "subsystem-attributed (plan hash == outcome digest), but "+OutcomeNotSealed+": the plan hash has no sealed witness")
			return
		}
		r.add("plan_hash_binding", CheckPass, "subsystem-attributed (plan hash == outcome digest)")
		return
	}
	r.add("plan_hash_binding", CheckFail, "PlanHash has no binding witness in the bundle")
}

// checkBundleHash recomputes the bundle's hash over its sealed content and holds the stored BundleHash to it (brief 28cd, L3124). Under the
// rule every bundle is sealed under (BundleHashRuleSealedDigests) the hash covers the outcome digest, the anchor candidate digest, the plan
// content hash, the sealed block height and every step's per-category gas, so a bundle whose outcome digest was swapped after it was sealed
// fails here, and one whose stored BundleHash was rewritten to match fails anchor_proof, where the anchored batch root still holds the sealed
// hash. A bundle sealed under the legacy rule (anchored before the rule existed) recomputes under it and passes, and the check says what that
// rule leaves unsealed; OutcomeDigestSealed stays false for it.
func (r *Report) checkBundleHash(bundle *evidence.EvidenceBundle, ok bool) {
	if !ok {
		r.add("bundle_hash", CheckFail, "bundle did not parse")
		return
	}
	got, err := bundle.ComputeBundleHash()
	if err != nil {
		r.add("bundle_hash", CheckFail, "recompute bundle hash: "+err.Error())
		return
	}
	if got != bundle.BundleHash {
		r.add("bundle_hash", CheckFail, fmt.Sprintf("the bundle's content hashes to %x…, not its sealed BundleHash %x… (the bundle was changed after it was sealed)", got[:8], bundle.BundleHash[:8]))
		return
	}
	if !bundle.BundleHashCoversSealedDigests() {
		r.legacyHashRule = true
		r.add("bundle_hash", CheckPass, "the content recomputes to BundleHash under the LEGACY rule the bundle was sealed under, which does not cover its outcome digest, step gas, plan content hash or sealed height: "+OutcomeNotSealed+" (the outcome is proven only by a matching replay)")
		return
	}
	r.add("bundle_hash", CheckPass, "the sealed content (outcome digest, anchor candidate, plan content hash, sealed height, step gas) recomputes to BundleHash")
}

func (r *Report) checkOutcomeDigestBinding(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, ok bool) {
	if !ok {
		r.add("outcome_digest_binding", CheckFail, "bundle did not parse")
		return
	}
	if pkg.OutcomeDigest == ([32]byte{}) {
		r.add("outcome_digest_binding", CheckFail, "OutcomeDigest is zero")
		return
	}
	if bundle.OutcomeDigest != pkg.OutcomeDigest {
		r.add("outcome_digest_binding", CheckFail, "OutcomeDigest does not match the embedded bundle")
		return
	}
	if checkStatusOf(r, "bundle_hash") == CheckPass && bundle.BundleHashCoversSealedDigests() {
		r.OutcomeDigestSealed = true
		r.add("outcome_digest_binding", CheckPass, "outcome digest bound to the bundle and sealed into its BundleHash")
		return
	}
	if r.legacyHashRule {
		r.add("outcome_digest_binding", CheckSkip, OutcomeNotSealed+": the outcome digest is bound to the package, not sealed into the bundle's hash, so nothing is claimed of it")
		return
	}
	r.add("outcome_digest_binding", CheckFail, "the outcome digest is not sealed: the bundle hash did not recompute")
}

// OutcomeNotSealed is what every check and receipt says of a bundle sealed under the legacy bundle hash rule (rule 1, written as an absent
// bundleHashRule; every bundle sealed since is rule 2): its BundleHash does not cover the outcome digest or the steps' gas categories, so no
// level, receipt line or claim rests on them (brief 28cd, L3124, main's condition).
const OutcomeNotSealed = "outcome not sealed (bundle hash rule 1)"

// checkStatusOf is the status of the named check, or "" when it has not run.
func checkStatusOf(r *Report, name string) CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

func (r *Report) checkEvidenceChain(pkg *evidence.PortableEvidencePackage) {
	for i := range pkg.InclusionProofs {
		p := pkg.InclusionProofs[i]
		if !evidence.VerifyMerkleInclusionProof(&p) {
			r.add("evidence_chain", CheckFail, fmt.Sprintf("inclusion proof %d failed", i))
			return
		}
	}
	if len(pkg.InclusionProofs) == 0 {
		r.add("evidence_chain", CheckPass, "no inclusion proofs to verify")
		return
	}
	r.add("evidence_chain", CheckPass, fmt.Sprintf("%d inclusion proof(s) verified", len(pkg.InclusionProofs)))
}

func (r *Report) checkPluginInventory(pkg *evidence.PortableEvidencePackage) {
	for i, pv := range pkg.PluginVersions {
		if pv.PluginID == "" || pv.Version == "" || pv.ImplementationHash == "" {
			r.add("plugin_inventory", CheckFail, fmt.Sprintf("PluginVersions[%d] partially populated", i))
			return
		}
	}
	r.add("plugin_inventory", CheckPass, fmt.Sprintf("%d plugin version(s)", len(pkg.PluginVersions)))
}

// checkAnchorProof decides whether the bundle is anchored, from evidence this verifier checks itself: the anchor record names this
// bundle and the bundle hash recomputed from the bundle's content, and the bundle's AnchorInclusion proves that hash is a leaf of
// the batch root it names (a one-leaf batch for a bundle anchored alone). It returns true only then.
//
// The node-set anchorStatus is never read for the verdict: a bundle that says "anchored" with no inclusion proof is not anchored
// here (a SKIP that leaves the proof level at L0); an inclusion or anchor record that is present and wrong is a FAIL, a tamper.
func (r *Report) checkAnchorProof(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, parsed bool) bool {
	if !parsed {
		r.add("anchor_proof", CheckSkip, "bundle did not parse")
		return false
	}
	if pkg.AnchorProof == nil && bundle.AnchorInclusion == nil {
		detail := "bundle carries no anchor proof"
		if bundle.Anchor == evidence.AnchorStatusAnchored || bundle.Anchor == evidence.AnchorStatusVerified {
			detail = fmt.Sprintf("the bundle's anchorStatus says %q but it carries no anchor proof; a node-set status is not evidence (not anchored)", bundle.Anchor)
		}
		r.add("anchor_proof", CheckSkip, detail)
		return false
	}
	if pkg.AnchorProof == nil {
		r.add("anchor_proof", CheckFail, "the bundle carries an anchor inclusion but the package has no AnchorProof record")
		return false
	}
	if bundle.AnchorInclusion == nil {
		r.add("anchor_proof", CheckSkip, "the package carries an AnchorProof record but the bundle has no inclusion proof of its hash in the anchored batch (not anchored)")
		return false
	}
	if pkg.AnchorProof.BundleID != bundle.ID {
		r.add("anchor_proof", CheckFail, "AnchorProof.BundleID does not match bundle")
		return false
	}
	if bundle.AnchorTxHash != "" && pkg.AnchorTxHash != bundle.AnchorTxHash {
		r.add("anchor_proof", CheckFail, "AnchorTxHash cross-binding mismatch")
		return false
	}
	leaf, err := bundle.ComputeBundleHash()
	if err != nil {
		r.add("anchor_proof", CheckFail, "recompute bundle hash: "+err.Error())
		return false
	}
	if pkg.AnchorProof.BundleHash != leaf {
		r.add("anchor_proof", CheckFail, "the anchor record's BundleHash is not the hash of this bundle's content")
		return false
	}
	if err := evidence.VerifyAnchorInclusion(leaf, bundle.AnchorInclusion); err != nil {
		r.add("anchor_proof", CheckFail, err.Error())
		return false
	}
	// The root is named by its first 12 bytes: the full value is in the bundle, and a rendered report carries no 32-byte hex run a
	// secret scanner cannot tell from key material (infrix-core's agent self-test, brief 28bj).
	// The one batch tree hashes sorted pairs (brief 28bk row 2): the path proves membership at the batch's depth, never the position, so
	// the report states membership and says the position is not bound; LeafIndex is not reported as verified.
	r.add("anchor_proof", CheckPass, fmt.Sprintf("bundle hash proven a member of the %d-leaf batch root %x… (the hash binds membership, not the leaf position)",
		bundle.AnchorInclusion.LeafCount, bundle.AnchorInclusion.BatchRoot[:12]))
	return true
}

// checkStateInclusion adds the state_inclusion check: a SKIP for a bundle that claims no state, a FAIL (and no L1/L2) for a state proof that does
// not verify, and a PASS naming the rung reached.
func (r *Report) checkStateInclusion(bundle *evidence.EvidenceBundle, parsed bool) stateVerdict {
	if !parsed {
		r.add("state_inclusion", CheckSkip, "bundle did not parse")
		return stateVerdict{}
	}
	v := checkStateProofs(bundle)
	switch {
	case v.Failure != "":
		r.add("state_inclusion", CheckFail, v.Failure)
		return stateVerdict{}
	case v.Account:
		r.add("state_inclusion", CheckPass, fmt.Sprintf("%d key(s) proven in their contract roots, and the contract roots in the bundle's state root (L2)", len(bundle.StorageProofs)))
	case v.Storage:
		r.add("state_inclusion", CheckPass, fmt.Sprintf("%d key(s) proven in their contract roots; no contract root is tied to the state root (L1)", len(bundle.StorageProofs)))
	default:
		r.add("state_inclusion", CheckSkip, "the bundle claims no contract state")
	}
	return v
}

// checkApprovalSignatures adds the approval_signatures check and returns whether every approval in the bundle carries a signature
// this verifier checked over the package's plan hash. A wrong signature or binding is a FAIL (a forged or tampered approval); an
// unsigned approval, or one in a scheme this verifier does not implement, is a SKIP that caps governance at G0.
func (r *Report) checkApprovalSignatures(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, parsed bool) bool {
	if !parsed {
		r.add("approval_signatures", CheckSkip, "bundle did not parse")
		return false
	}
	v := checkApprovalSignatures(bundle, pkg.PlanHash)
	switch {
	case v.Count == 0:
		r.add("approval_signatures", CheckSkip, "bundle records no approval (governance caps at G0)")
	case len(v.Failures) > 0:
		r.add("approval_signatures", CheckFail, strings.Join(v.Failures, "; "))
	case len(v.Uncheckable) > 0:
		r.add("approval_signatures", CheckSkip, "not credited (governance caps at G0): "+strings.Join(v.Uncheckable, "; "))
	default:
		r.add("approval_signatures", CheckPass, fmt.Sprintf("%d approval signature(s) verified over the plan hash", v.Count))
	}
	return v.Signed
}

// checkL0Anchor performs the live L0 confirmation and returns whether the
// anchor was independently confirmed against L0.
// checkStateRootProof adds the state_root_accumulator check (package stateroot holds the rule).
func (r *Report) checkStateRootProof(ctx context.Context, bundle *evidence.EvidenceBundle, opts Options) {
	var res stateroot.Result
	if opts.StateRootProofError != "" {
		res = stateroot.Result{Verdict: stateroot.VerdictFail, Detail: opts.StateRootProofError}
	} else {
		// the leaf is bound to the bundle by its OUTCOME id: the node recorded it at the moment it read its root to finalize that outcome
		res = stateroot.Check(ctx, opts.StateRootProof, bundle.StateRoot, bundle.OutcomeID, opts.StateRootAnchors)
	}
	if opts.RequireStateRootProof && res.Verdict == stateroot.VerdictSkip {
		res = stateroot.Result{Verdict: stateroot.VerdictFail, Detail: "a proven state root is required but it is not: " + res.Detail}
	}
	switch res.Verdict {
	case stateroot.VerdictPass:
		r.add(stateroot.CheckName, CheckPass, res.Detail)
	case stateroot.VerdictFail:
		r.add(stateroot.CheckName, CheckFail, res.Detail)
	default:
		r.add(stateroot.CheckName, CheckSkip, res.Detail)
	}
}

func (r *Report) checkL0Anchor(ctx context.Context, bundle *evidence.EvidenceBundle, anchored bool, confirmer L0AnchorConfirmer) bool {
	if !anchored {
		r.add("l0_anchor", CheckSkip, "bundle is not anchored")
		return false
	}
	if confirmer == nil {
		r.add("l0_anchor", CheckSkip, "no L0 endpoint supplied — anchor not independently confirmed (proof level caps at L3)")
		return false
	}
	if strings.TrimSpace(bundle.AnchorTxHash) == "" {
		r.add("l0_anchor", CheckFail, "anchored bundle has no AnchorTxHash to confirm")
		return false
	}
	conf, err := confirmer.ConfirmAnchor(ctx, bundle.AnchorTxHash, bundle.ID, bundle.BundleHash, bundle.AnchorBlock)
	if err != nil {
		r.add("l0_anchor", CheckFail, "L0 confirmation error: "+err.Error())
		return false
	}
	if !conf.Delivered {
		r.add("l0_anchor", CheckFail, "anchor transaction is not delivered/committed on L0")
		return false
	}
	if !conf.EntryMatches {
		r.add("l0_anchor", CheckFail, "L0 anchor entry does not commit to the bundle: "+conf.Detail)
		return false
	}
	detail := "L0 anchor confirmed"
	if conf.BlockHeight > 0 {
		detail = fmt.Sprintf("L0 anchor confirmed at block %d", conf.BlockHeight)
	}
	if conf.Detail != "" {
		detail += " (" + conf.Detail + ")"
	}
	r.add("l0_anchor", CheckPass, detail)
	return true
}

// checkExternalProof independently confirms the bundle's external/credential
// proof reference against its source chain and returns whether at least one was
// confirmed. This is the honest basis for governance level G2 — never the
// self-asserted evidence.ExternalProofRef.Verified flag (DX P0-5b/P1-4).
//
// Two routes confirm a proof (brief 28bk row 3, main's ruling (a)). EMBEDDED: every referenced proof carries the l0proof chain of the
// WriteData that holds its ProofHash as one whole data item on its Account, and each chain verifies against THIS verifier's pin (the
// compiled network pin or the relying party's Options.L0Pin, never the bundle's): offline, source embedded-proof. A chain that does not
// verify fails the check with its reason, and governance stays at G1. LIVE: otherwise an injected confirmer re-reads the proof from its
// source (source live-query). It returns whether the proofs are confirmed and whether the embedded route confirmed them.
func (r *Report) checkExternalProof(ctx context.Context, bundle *evidence.EvidenceBundle, opts Options) (confirmed, embedded bool) {
	if len(bundle.ExternalProofs) == 0 {
		r.add("external_proof", CheckSkip, "bundle references no external proof")
		return false, false
	}
	allEmbedded := true
	for i := range bundle.ExternalProofs {
		if len(bundle.ExternalProofs[i].L0Proof) == 0 {
			allEmbedded = false
		}
	}
	if allEmbedded {
		for i := range bundle.ExternalProofs {
			ep := &bundle.ExternalProofs[i]
			chain, err := l0proof.Decode(ep.L0Proof, nil)
			if err != nil {
				r.add("external_proof", CheckFail, fmt.Sprintf("external proof %d: embedded chain: %v (governance caps at G1)", i, err))
				return false, false
			}
			if why, unheld := unheldPin(chain.Incarnation, opts); unheld {
				r.add("external_proof", CheckSkip, fmt.Sprintf("external proof %d: embedded chain %s (governance caps at G1)", i, why))
				return false, false
			}
			res := l0proof.Verify(chain, l0proof.Expectation{AnchorAccount: ep.Account, Leaf: ep.ProofHash[:]}, l0Opts(opts))
			if !res.Verified {
				r.add("external_proof", CheckFail, fmt.Sprintf("external proof %d: embedded chain does not confirm it: %s (governance caps at G1)", i, res.Reason))
				return false, false
			}
		}
		r.add("external_proof", CheckPass, fmt.Sprintf("%d external proof(s) confirmed by embedded Accumulate chains against the verifier's pin", len(bundle.ExternalProofs)))
		return true, true
	}
	confirmer := opts.ExternalProofConfirmer
	if confirmer == nil {
		r.add("external_proof", CheckSkip, "no external-proof confirmer supplied and no embedded confirmation — external proof not independently confirmed (governance caps at G1)")
		return false, false
	}
	for i := range bundle.ExternalProofs {
		ep := bundle.ExternalProofs[i]
		conf, err := confirmer.ConfirmExternalProof(ctx, ep.SourceChain, ep.ProofType, ep.TxHash, ep.ProofHash, ep.BlockHeight)
		if err != nil {
			r.add("external_proof", CheckFail, "external proof confirmation error: "+err.Error())
			return false, false
		}
		if conf != nil && conf.Confirmed {
			detail := "external proof independently confirmed"
			if conf.Detail != "" {
				detail += " (" + conf.Detail + ")"
			}
			r.add("external_proof", CheckPass, detail)
			return true, false
		}
	}
	r.add("external_proof", CheckFail, "no referenced external proof could be independently confirmed")
	return false, false
}

// finalizeLevels sets the level fields + the overall Verified flag.
func (r *Report) finalizeLevels(proof assurance.ProofLevel, gov assurance.GovernanceLevel, require *RequiredLevel) {
	class := assurance.ClassFor(proof, gov, false)
	r.ProofLevel = proof.String()
	r.GovernanceLevel = gov.String()
	r.AssuranceClass = class.String()
	r.AssuranceMultiplier = class.Multiplier()
	r.Tier = proof.String() + "/" + gov.String()

	verified := !r.hasFailures()
	if require != nil {
		met := proof >= require.Proof && gov >= require.Governance
		r.RequireMet = &met
		if !met {
			r.add("require_level", CheckFail, fmt.Sprintf("achieved %s/%s, required %s/%s", proof.String(), gov.String(), require.Proof.String(), require.Governance.String()))
			verified = false
		} else {
			r.add("require_level", CheckPass, "achieved "+r.Tier+" meets "+require.Raw)
		}
	}
	r.Verified = verified
}
