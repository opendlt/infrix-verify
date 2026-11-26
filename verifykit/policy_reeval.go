// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"encoding/hex"
	"fmt"

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
// operand the subject does not carry (the node's state is not provable offline).
func (r *Report) checkPolicyReevaluation(bundle *evidence.EvidenceBundle, parsed bool, pins map[string][32]byte) bool {
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
		out, err := doc.Decide(&policyeval.SubjectOnlyContext{Subject: subjectOf(ev.Subject)})
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
	detail := fmt.Sprintf("%d content-addressed policies re-evaluated with the node's evaluator body; every one allows", len(evals))
	if pins == nil {
		detail += " (no policy registry pinned: the hashes are reported for the relying party to compare)"
	}
	r.add(name, CheckPass, detail)
	return true
}

func subjectOf(s evidence.PolicySubject) policyeval.Subject {
	return policyeval.Subject{Actor: s.Actor, Contract: s.Contract, Function: s.Function, BlockHeight: s.BlockHeight, Amount: s.Amount}
}
