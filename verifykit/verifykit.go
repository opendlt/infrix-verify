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
	"github.com/opendlt/infrix-verify/witness"
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

	report.checkPlanHashBinding(pkg, &bundle, bundleParsed)
	report.checkOutcomeDigestBinding(pkg, &bundle, bundleParsed)
	report.checkEvidenceChain(pkg)
	report.checkPluginInventory(pkg)

	anchored := bundleParsed && (bundle.Anchor == evidence.AnchorStatusAnchored || bundle.Anchor == evidence.AnchorStatusVerified)
	report.checkAnchorProof(pkg, &bundle, anchored)

	// 9-11. Live L0 confirmation — fetch the anchor tx directly from L0.
	l0Confirmed := report.checkL0Anchor(ctx, &bundle, anchored, opts.L0Confirmer)
	externalProofConfirmed := report.checkExternalProof(ctx, &bundle, opts.ExternalProofConfirmer)

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
	proof := computeProofLevel(anchored, l0Confirmed)
	gov := computeGovernanceLevel(&bundle, bundleParsed, externalProofConfirmed)
	report.finalizeLevels(proof, gov, opts.Require)

	// Derived layered-verification flags (mirror the Nexus inspector).
	report.L0Verified = l0Confirmed
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

// add appends a check.
func (r *Report) add(name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
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
	// Subsystem-attributed fallback: PlanHash may equal OutcomeDigest.
	if pkg.PlanHash == pkg.OutcomeDigest {
		r.add("plan_hash_binding", CheckPass, "subsystem-attributed (plan hash == outcome digest)")
		return
	}
	r.add("plan_hash_binding", CheckFail, "PlanHash has no binding witness in the bundle")
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
	r.add("outcome_digest_binding", CheckPass, "outcome digest bound to the bundle")
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

func (r *Report) checkAnchorProof(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, anchored bool) {
	if !anchored {
		r.add("anchor_proof", CheckSkip, "bundle is not anchored")
		return
	}
	if pkg.AnchorProof == nil {
		r.add("anchor_proof", CheckFail, "anchored bundle missing AnchorProof")
		return
	}
	if pkg.AnchorProof.BundleID != bundle.ID {
		r.add("anchor_proof", CheckFail, "AnchorProof.BundleID does not match bundle")
		return
	}
	if bundle.AnchorTxHash != "" && pkg.AnchorTxHash != bundle.AnchorTxHash {
		r.add("anchor_proof", CheckFail, "AnchorTxHash cross-binding mismatch")
		return
	}
	r.add("anchor_proof", CheckPass, "anchor proof bound to the bundle")
}

// checkL0Anchor performs the live L0 confirmation and returns whether the
// anchor was independently confirmed against L0.
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
func (r *Report) checkExternalProof(ctx context.Context, bundle *evidence.EvidenceBundle, confirmer ExternalProofConfirmer) bool {
	if len(bundle.ExternalProofs) == 0 {
		r.add("external_proof", CheckSkip, "bundle references no external proof")
		return false
	}
	if confirmer == nil {
		r.add("external_proof", CheckSkip, "no external-proof confirmer supplied — external proof not independently confirmed (governance caps at G1)")
		return false
	}
	for i := range bundle.ExternalProofs {
		ep := bundle.ExternalProofs[i]
		conf, err := confirmer.ConfirmExternalProof(ctx, ep.SourceChain, ep.ProofType, ep.TxHash, ep.ProofHash, ep.BlockHeight)
		if err != nil {
			r.add("external_proof", CheckFail, "external proof confirmation error: "+err.Error())
			return false
		}
		if conf != nil && conf.Confirmed {
			detail := "external proof independently confirmed"
			if conf.Detail != "" {
				detail += " (" + conf.Detail + ")"
			}
			r.add("external_proof", CheckPass, detail)
			return true
		}
	}
	r.add("external_proof", CheckFail, "no referenced external proof could be independently confirmed")
	return false
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
