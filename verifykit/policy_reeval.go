// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opendlt/infrix-verify/govproof"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-schema/policyeval"
)

// PolicyReevaluation is the report's record of one policy this verifier re-ran (native proof plan phase 6, brief 28bi).
type PolicyReevaluation struct {
	PolicyType string `json:"policyType"`
	// Hash is the content address the verifier recomputed and matched.
	Hash string `json:"hash"`
	// Effect and MatchedRule are what the verifier's own re-evaluation decided; empty when it could not decide.
	Effect      string `json:"effect,omitempty"`
	MatchedRule string `json:"matchedRule,omitempty"`
	// Pinned is true when the relying party pinned this policy type and the hash is the pinned one.
	Pinned bool `json:"pinned"`
}

// checkPolicyReevaluation re-runs every content-addressed policy the bundle says its plan was decided under, with policyeval (the node's
// own evaluator body), over the subject the bundle commits to, and reports whether every one ALLOWS. A recorded decision is never read for
// it. G0 is credited only when this returns true.
//
// The check FAILS (the bundle lies) when a policy's content does not hash to its PolicyRef.Hash (BD-06), when the content is not a valid
// canonical policy document, when a re-evaluation denies (NL-03: a recorded allow the policy does not reproduce), or when a policy is not
// the one the relying party pinned for its type. It is a SKIP that credits no G0, and fails nothing, when there is nothing to re-run, when
// a recorded decision has no re-evaluable policy beside it (in order and by type), when a pinned type is missing, or when a policy reads an
// operand the subject does not carry and no proof covers (actor::role is proven by the bundle's RoleRegistryProof, L3112).
//
// When approvals signed the plan (any approval carries a plan hash), every re-evaluated subject must be bound into the plan hash they signed
// (brief 28bu row 2, the L3008 (b) ruling): planHash must equal evidence.BindPlanHash(bundle.PlanContentHash, the evaluations). A bundle
// whose subjects are not bound is a SKIP that credits no G0 (an approved plan's subjects are node-asserted otherwise); a binding that does not
// recompute FAILS (the subjects or the policies are not the ones the approvals signed).
func (r *Report) checkPolicyReevaluation(bundle *evidence.EvidenceBundle, parsed bool, pins map[string][32]byte, planHash [32]byte, opts Options) bool {
	const name = "policy_reevaluation"
	if !parsed {
		r.add(name, CheckFail, "bundle did not parse")
		return false
	}
	evals := bundle.PolicyEvaluations
	if len(evals) == 0 {
		r.add(name, CheckSkip, "the bundle carries no content-addressed policy to re-evaluate; G0 is not credited")
		return false
	}
	results := make([]PolicyReevaluation, 0, len(evals))
	defer func() { r.PolicyReevaluations = results }()

	// actor::role operands are answered only from the role registry proven against the bundle's StateRoot (infrix-core L3112): a proof that
	// does not recompute FAILS; an actor it does not cover leaves actor::role unproven, exactly as the subject-only context refuses it
	var provenRoles map[string][]string
	if bundle.RoleRegistryProof != nil {
		var err error
		if provenRoles, err = VerifyRoleRegistryProof(bundle.StateRoot, bundle.RoleRegistryProof); err != nil {
			r.add(name, CheckFail, fmt.Sprintf("the role registry proof does not verify against the bundle's state root: %v", err))
			return false
		}
	}
	// actor::has_key is answered through the node's own body (policyeval.ResolveActorHasKey) from the key pages and key books the bundle proves
	// under the pin (infrix-core L3196): a proven page answers from its proven entries (true or false), a page past a proven book's page count is
	// a proven false, a proof that does not verify FAILS, and any other page leaves actor::has_key unproven (an absent identity or key book is not
	// provable from Accumulate's receipts, policyeval.ErrAbsenceNotProvable)
	provenPages, err := verifiedKeyPages(bundle, opts)
	if err != nil {
		r.add(name, CheckFail, err.Error())
		return false
	}
	provenBooks, err := verifiedKeyBooks(bundle, opts)
	if err != nil {
		r.add(name, CheckFail, err.Error())
		return false
	}
	provedActors := 0

	var undecided string
	for i, ev := range evals {
		got := policyeval.ContentHash(ev.Policy.Content)
		res := PolicyReevaluation{PolicyType: ev.PolicyType, Hash: hex.EncodeToString(got[:])}
		if got != ev.Policy.Hash {
			r.add(name, CheckFail, fmt.Sprintf("policy %d (%s): content hashes to %x, not its PolicyRef.Hash %x", i, ev.PolicyType, got, ev.Policy.Hash))
			return false
		}
		doc, err := policyeval.DecodeDocument(ev.Policy.Content)
		if err != nil {
			r.add(name, CheckFail, fmt.Sprintf("policy %d (%s): %v", i, ev.PolicyType, err))
			return false
		}
		if doc.Type != ev.PolicyType {
			r.add(name, CheckFail, fmt.Sprintf("policy %d: the evaluation names type %q, the policy document is type %q", i, ev.PolicyType, doc.Type))
			return false
		}
		if pins != nil {
			pin, ok := pins[ev.PolicyType]
			if ok && pin != got {
				r.add(name, CheckFail, fmt.Sprintf("policy %d (%s): hash %x is not the pinned %x", i, ev.PolicyType, got, pin))
				return false
			}
			res.Pinned = ok
		}
		roles, proven := provenRoles[evidence.CanonicalRoleHolder(ev.Subject.Actor)]
		if proven {
			provedActors++
		}
		out, err := doc.Decide(&policyeval.ProvenRolesContext{Subject: subjectOf(ev.Subject), ActorRoles: roles, ActorProven: proven, ProvenPages: provenPages, ProvenBooks: provenBooks})
		if err != nil {
			if undecided == "" {
				undecided = fmt.Sprintf("policy %d (%s) cannot be re-evaluated offline: %v", i, ev.PolicyType, err)
			}
			results = append(results, res)
			continue
		}
		res.Effect, res.MatchedRule = string(out.Effect), out.MatchedRule
		results = append(results, res)
		if !out.Allowed() {
			r.add(name, CheckFail, fmt.Sprintf("policy %d (%s) re-evaluates to %s (%s); the bundle records it as decided under it", i, ev.PolicyType, out.Effect, out.AuditMsg))
			return false
		}
	}
	if undecided != "" {
		r.add(name, CheckSkip, undecided+"; G0 is not credited")
		return false
	}
	// Every recorded decision must be one of these re-evaluations, in order and by type: a decision with no re-evaluable policy beside it
	// was not re-run, so it cannot be credited.
	if len(bundle.PolicyDecisions) != len(evals) {
		r.add(name, CheckSkip, fmt.Sprintf("%d recorded policy decisions, %d re-evaluable policies; a decision without its policy is not re-run, so G0 is not credited", len(bundle.PolicyDecisions), len(evals)))
		return false
	}
	for i, d := range bundle.PolicyDecisions {
		if d.PolicyType != evals[i].PolicyType {
			r.add(name, CheckSkip, fmt.Sprintf("recorded decision %d is type %q, re-evaluable policy %d is type %q; G0 is not credited", i, d.PolicyType, i, evals[i].PolicyType))
			return false
		}
	}
	for t := range pins {
		found := false
		for _, ev := range evals {
			if ev.PolicyType == t {
				found = true
				break
			}
		}
		if !found {
			r.add(name, CheckSkip, fmt.Sprintf("the relying party pinned policy type %q and the bundle carries no policy of that type; G0 is not credited", t))
			return false
		}
	}
	approved := false
	for _, ae := range bundle.ApprovalEvidence {
		if ae.PlanHash != ([32]byte{}) {
			approved = true
			break
		}
	}
	bound := ""
	if approved {
		if bundle.PlanContentHash == ([32]byte{}) {
			r.add(name, CheckSkip, "approvals signed the plan, but the re-evaluated subjects are not bound into the plan hash they signed (the bundle carries no plan content hash); G0 is not credited")
			return false
		}
		if got := evidence.BindPlanHash(bundle.PlanContentHash, evals); got != planHash {
			r.add(name, CheckFail, fmt.Sprintf("the re-evaluated policies and subjects bind to plan hash %x, not the %x the approvals signed", got, planHash))
			return false
		}
		bound = "; every subject is bound into the plan hash the approvals signed"
	}
	detail := fmt.Sprintf("%d content-addressed policies re-evaluated with the node's evaluator body; every one allows%s", len(evals), bound)
	if provedActors > 0 {
		detail += fmt.Sprintf("; actor::role answered for %d evaluation(s) from the role registry proven against the bundle's state root", provedActors)
	}
	if pins == nil {
		detail += " (no policy registry pinned: the hashes are reported for the relying party to compare)"
	}
	r.add(name, CheckPass, detail)
	return true
}

func subjectOf(s evidence.PolicySubject) policyeval.Subject {
	return policyeval.Subject{Actor: s.Actor, Contract: s.Contract, Function: s.Function, BlockHeight: s.BlockHeight, Amount: s.Amount}
}

// verifiedKeyPages is the key pages (URL, lower case) the bundle proves under the verifier's pin, each with its proven entries, from its approval
// pages (KeyPageProofs) and the pages its policies read (OperandPageProofs): every proof is verified (govproof.VerifyKeyPage), a proof that does
// not verify is an error, and a proof captured under a pin this verifier does not hold proves nothing.
func verifiedKeyPages(bundle *evidence.EvidenceBundle, opts Options) (map[string]policyeval.KeyPageEntries, error) {
	pages := map[string]policyeval.KeyPageEntries{}
	all := append(append([]json.RawMessage(nil), bundle.KeyPageProofs...), bundle.OperandPageProofs...)
	for i, raw := range all {
		var p govproof.KeyPageProof
		if err := decodeStrict(raw, &p); err != nil {
			return nil, fmt.Errorf("key-page proof %d: %v", i, err)
		}
		if _, unheld := unheldPin(p.Incarnation, opts); unheld {
			continue
		}
		res := govproof.VerifyKeyPage(&p, l0Opts(opts))
		if !res.Verified {
			return nil, fmt.Errorf("key-page proof %d: %s", i, res.Reason)
		}
		pages[strings.ToLower(res.Page.URL)] = policyeval.KeyPageEntries{KeyHashes: res.Page.KeyHashes, Delegates: res.Page.Delegates}
	}
	return pages, nil
}

// verifiedKeyBooks is the key books (URL, lower case) the bundle proves under the verifier's pin (OperandBookProofs), each with its proven page
// count: every proof is verified (govproof.VerifyKeyBook), a proof that does not verify is an error, and a proof captured under a pin this
// verifier does not hold proves nothing.
func verifiedKeyBooks(bundle *evidence.EvidenceBundle, opts Options) (map[string]uint64, error) {
	books := map[string]uint64{}
	for i, raw := range bundle.OperandBookProofs {
		var p govproof.KeyBookProof
		if err := decodeStrict(raw, &p); err != nil {
			return nil, fmt.Errorf("key-book proof %d: %v", i, err)
		}
		if _, unheld := unheldPin(p.Incarnation, opts); unheld {
			continue
		}
		res := govproof.VerifyKeyBook(&p, l0Opts(opts))
		if !res.Verified {
			return nil, fmt.Errorf("key-book proof %d: %s", i, res.Reason)
		}
		books[strings.ToLower(res.Book.URL)] = res.Book.PageCount
	}
	return books, nil
}
