// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
)

// TestS28buTheReevaluatedSubjectsMustBindIntoThePlanHashTheApprovalsSigned (brief 28bu row 2, the L3008 (b) ruling): when approvals signed
// the plan, G0 is credited only if every re-evaluated subject is bound into the plan hash they signed. The bound bundle passes; a subject
// changed after the approvals signed FAILS; a bundle with no plan content hash is a SKIP crediting no G0; a bundle nobody approved keeps G0
// from the re-evaluation over its sealed subject.
func TestS28buTheReevaluatedSubjectsMustBindIntoThePlanHashTheApprovalsSigned(t *testing.T) {
	content := planContentVK()
	evals := func() []evidence.PolicyEvaluation {
		return []evidence.PolicyEvaluation{transferEvaluation(t, transferPolicy(), 50)}
	}
	decisions := []evidence.DecisionProofRef{{PolicyType: "transfer", RuleID: "allow", Decision: "allow", BlockHeight: 1}}
	signed := evidence.BindPlanHash(content, evals())
	run := func(b *evidence.EvidenceBundle, planHash [32]byte) (bool, CheckStatus, string) {
		r := &Report{}
		ok := r.checkPolicyReevaluation(b, true, nil, planHash)
		st, d := checkResult(r, "policy_reevaluation")
		return ok, st, d
	}
	bound := &evidence.EvidenceBundle{PolicyDecisions: decisions, PolicyEvaluations: evals(), PlanContentHash: content,
		ApprovalEvidence: []evidence.ApprovalEvidenceRef{{PlanHash: signed}}}
	if ok, st, d := run(bound, signed); !ok || st != CheckPass || !strings.Contains(d, "bound into the plan hash") {
		t.Fatalf("the bound bundle: credited=%v %s %q; want a pass naming the binding", ok, st, d)
	}
	moved := &evidence.EvidenceBundle{PolicyDecisions: decisions, PolicyEvaluations: evals(), PlanContentHash: content,
		ApprovalEvidence: []evidence.ApprovalEvidenceRef{{PlanHash: signed}}}
	moved.PolicyEvaluations[0].Subject.Actor = "acc://mallory.acme"
	if ok, st, d := run(moved, signed); ok || st != CheckFail || !strings.Contains(d, "not the") {
		t.Fatalf("a subject changed after the approvals signed: credited=%v %s %q; want a failure naming both plan hashes", ok, st, d)
	}
	unbound := &evidence.EvidenceBundle{PolicyDecisions: decisions, PolicyEvaluations: evals(),
		ApprovalEvidence: []evidence.ApprovalEvidenceRef{{PlanHash: content}}}
	if ok, st, d := run(unbound, content); ok || st != CheckSkip || !strings.Contains(d, "not bound") {
		t.Fatalf("an approved bundle with no plan content hash: credited=%v %s %q; want a skip crediting no G0", ok, st, d)
	}
	unapproved := &evidence.EvidenceBundle{PolicyDecisions: decisions, PolicyEvaluations: evals()}
	if ok, st, _ := run(unapproved, [32]byte{}); !ok || st != CheckPass {
		t.Fatalf("a bundle nobody approved: credited=%v %s; want G0 from the re-evaluation over its sealed subject", ok, st)
	}
}
