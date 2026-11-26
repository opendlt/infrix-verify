package verifykit

import (
	"context"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/assurance"
	evidence "github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-schema/policyeval"
)

var (
	govUngoverned = assurance.GovernanceLevelUngoverned.String()
	govG0         = assurance.GovernanceLevelPolicyPassed.String()
)

// transferPolicy is the fixture's governing policy: deny over the cap, allow an identified actor, deny by default.
func transferPolicy() *policyeval.PolicyDocument {
	return &policyeval.PolicyDocument{
		ID: "transfer-cap", Name: "transfer cap", Type: "transfer", Version: 1, DefaultEffect: policyeval.EffectDeny,
		Rules: []policyeval.DocumentRule{
			{ID: "cap", Priority: 10, Condition: `scope::amount() > 1000`, Effect: policyeval.EffectDeny, AuditMsg: "over the cap", Enabled: true},
			{ID: "allow", Priority: 100, Condition: `actor::identity() != ""`, Effect: policyeval.EffectAllow, AuditMsg: "identified actor", Enabled: true},
		},
	}
}

func policyRef(t *testing.T, d *policyeval.PolicyDocument) evidence.PolicyRef {
	t.Helper()
	content, err := policyeval.EncodeDocument(d)
	if err != nil {
		t.Fatalf("encode policy: %v", err)
	}
	return evidence.PolicyRef{Hash: policyeval.ContentHash(content), Content: content}
}

func transferEvaluation(t *testing.T, d *policyeval.PolicyDocument, amount float64) evidence.PolicyEvaluation {
	t.Helper()
	return evidence.PolicyEvaluation{PolicyType: d.Type, ScopeKey: "global", Policy: policyRef(t, d),
		Subject: evidence.PolicySubject{Actor: "acc://alice.acme", Function: "transfer", BlockHeight: 1, Amount: &amount}}
}

func verifyWith(t *testing.T, pre func(*evidence.EvidenceBundle), opts Options) *Report {
	t.Helper()
	return Verify(context.Background(), buildPortableWith(t, false, [32]byte{7}, "outcome-vk", pre, nil), opts)
}

func checkResult(r *Report, name string) (CheckStatus, string) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status, c.Detail
		}
	}
	return "", ""
}

// PV-G0-01: the verifier re-evaluates the content-addressed policy over the committed subject and reaches allow, so G0 is credited (and only
// G0: the fixture's approval is signed but no key-page proof proves its key, so the cumulative ladder stops at G0 and names why, main ruling
// 2026-11-26). Bite: with the policy re-evaluation removed, the same bundle is ungoverned.
func TestPVG001_ReevaluatedPolicyAllowsAndCreditsG0(t *testing.T) {
	r := verifyWith(t, nil, Options{})
	if st, d := checkResult(r, "policy_reevaluation"); st != CheckPass {
		t.Fatalf("policy_reevaluation %s: %s", st, d)
	}
	if r.GovernanceLevel != govG0 {
		t.Fatalf("governance %s", r.GovernanceLevel)
	}
	if st, d := checkResult(r, "approval_key_pages"); st != CheckSkip || !strings.Contains(d, "no key-page proofs") {
		t.Fatalf("approval_key_pages %s: %s; want the missing key-page proofs named", st, d)
	}
	if len(r.PolicyReevaluations) != 1 || r.PolicyReevaluations[0].Effect != "allow" || r.PolicyReevaluations[0].MatchedRule != "allow" {
		t.Fatalf("report: %+v", r.PolicyReevaluations)
	}
	bite := verifyWith(t, func(b *evidence.EvidenceBundle) { b.PolicyEvaluations = nil }, Options{})
	if bite.GovernanceLevel != govUngoverned {
		t.Fatalf("bite: a recorded allow with no re-evaluable policy reached %s", bite.GovernanceLevel)
	}
	if st, _ := checkResult(bite, "policy_reevaluation"); st != CheckSkip {
		t.Fatalf("a bundle with nothing to re-evaluate is uncredited, not failed: %s", st)
	}
}

// NL-03: a recorded "allow" whose re-evaluation denies (the subject's amount is over the cap) is ungoverned, and the check fails.
func TestNL03_RecordedAllowThatReevaluatesToDenyIsUngoverned(t *testing.T) {
	r := verifyWith(t, func(b *evidence.EvidenceBundle) {
		b.PolicyEvaluations = []evidence.PolicyEvaluation{transferEvaluation(t, transferPolicy(), 5000)}
	}, Options{})
	st, d := checkResult(r, "policy_reevaluation")
	if st != CheckFail || !strings.Contains(d, "re-evaluates to deny") {
		t.Fatalf("policy_reevaluation %s: %s", st, d)
	}
	if r.GovernanceLevel != govUngoverned || r.Verified {
		t.Fatalf("governance %s verified %t", r.GovernanceLevel, r.Verified)
	}
}

// BD-06: policy content whose hash differs from PolicyRef.Hash fails, whether the content or the hash was changed. Bite: the matching pair
// passes (PV-G0-01).
func TestBD06_PolicyContentWhoseHashDiffersFails(t *testing.T) {
	permissive := transferPolicy()
	permissive.Rules = permissive.Rules[1:] // the cap removed
	for name, mutate := range map[string]func(*evidence.EvidenceBundle){
		"content swapped": func(b *evidence.EvidenceBundle) {
			b.PolicyEvaluations[0].Policy.Content = policyRef(t, permissive).Content
		},
		"hash swapped": func(b *evidence.EvidenceBundle) { b.PolicyEvaluations[0].Policy.Hash[0] ^= 1 },
	} {
		r := verifyWith(t, mutate, Options{})
		st, d := checkResult(r, "policy_reevaluation")
		if st != CheckFail || !strings.Contains(d, "not its PolicyRef.Hash") {
			t.Errorf("%s: %s %s", name, st, d)
		}
		if r.GovernanceLevel != govUngoverned {
			t.Errorf("%s: governance %s", name, r.GovernanceLevel)
		}
	}
}

// A policy that reads the node's state (a role) cannot be re-evaluated offline, a decision with no policy beside it is not re-run, and a
// pinned registry must match: each credits no G0. Bite: the pinned hash of the real policy credits it and reports it pinned.
func TestG0_UnprovableUncoveredAndUnpinnedPoliciesCreditNothing(t *testing.T) {
	role := transferPolicy()
	role.Rules[0] = policyeval.DocumentRule{ID: "admin", Priority: 1, Condition: `actor::role("admin") == true`, Effect: policyeval.EffectAllow, Enabled: true}
	cases := map[string]struct {
		pre  func(*evidence.EvidenceBundle)
		pins map[string][32]byte
		want CheckStatus
	}{
		"state operand": {func(b *evidence.EvidenceBundle) {
			b.PolicyEvaluations = []evidence.PolicyEvaluation{transferEvaluation(t, role, 50)}
		}, nil, CheckSkip},
		"uncovered decision": {func(b *evidence.EvidenceBundle) {
			b.PolicyDecisions = append(b.PolicyDecisions, evidence.DecisionProofRef{PolicyType: "governance", Decision: "allow"})
		}, nil, CheckSkip},
		"wrong pin":   {nil, map[string][32]byte{"transfer": {9}}, CheckFail},
		"missing pin": {nil, map[string][32]byte{"governance": {9}}, CheckSkip},
		"type relabelled": {func(b *evidence.EvidenceBundle) {
			b.PolicyEvaluations[0].PolicyType = "governance"
			b.PolicyDecisions[0].PolicyType = "governance"
		}, nil, CheckFail},
	}
	for name, c := range cases {
		r := verifyWith(t, c.pre, Options{PinnedPolicies: c.pins})
		if st, d := checkResult(r, "policy_reevaluation"); st != c.want {
			t.Errorf("%s: %s %s", name, st, d)
		}
		if r.GovernanceLevel != govUngoverned {
			t.Errorf("%s: governance %s", name, r.GovernanceLevel)
		}
	}
	pinned := verifyWith(t, nil, Options{PinnedPolicies: map[string][32]byte{"transfer": policyRef(t, transferPolicy()).Hash}})
	if pinned.GovernanceLevel != govG0 || !pinned.PolicyReevaluations[0].Pinned {
		t.Fatalf("bite: the pinned policy: %s %+v", pinned.GovernanceLevel, pinned.PolicyReevaluations)
	}
}

var govRank = map[string]int{
	assurance.GovernanceLevelUngoverned.String():           0,
	assurance.GovernanceLevelPolicyPassed.String():         1,
	assurance.GovernanceLevelThresholdApproved.String():    2,
	assurance.GovernanceLevelCredentialedAnchored.String(): 3,
}

// FZ-02 for the policy input: the governance level is monotone in the policy evidence. Removing any subset of the re-evaluable policies
// never raises the level (removing any one leaves the bundle ungoverned), and a random subject mutation never raises it either. Bite: the
// full bundle reaches G0 (its approval's key is not proven on a page, so the ladder stops there).
func TestFZ02_GovernanceIsMonotoneInPolicyEvidence(t *testing.T) {
	other := transferPolicy()
	other.ID, other.Type = "gov", "governance"
	two := func(b *evidence.EvidenceBundle) {
		b.PolicyDecisions = append(b.PolicyDecisions, evidence.DecisionProofRef{PolicyType: "governance", Decision: "allow"})
		b.PolicyEvaluations = append(b.PolicyEvaluations, transferEvaluation(t, other, 10))
	}
	full := verifyWith(t, two, Options{})
	base := govRank[full.GovernanceLevel]
	if base != 1 {
		t.Fatalf("full bundle: %s", full.GovernanceLevel)
	}
	rng := rand.New(rand.NewSource(28))
	for i := 0; i < 40; i++ {
		keep := rng.Intn(4)
		amt := rng.Float64() * 3000
		mutateAmount := i%2 == 1
		r := verifyWith(t, func(b *evidence.EvidenceBundle) {
			two(b)
			var kept []evidence.PolicyEvaluation
			for j, ev := range b.PolicyEvaluations {
				if keep&(1<<j) != 0 {
					kept = append(kept, ev)
				}
			}
			if len(kept) > 0 && mutateAmount {
				kept[0].Subject.Amount = &amt
			}
			b.PolicyEvaluations = kept
		}, Options{})
		if govRank[r.GovernanceLevel] > base {
			t.Fatalf("case %d (keep %b, amount %v): %s outranks the full bundle", i, keep, amt, r.GovernanceLevel)
		}
		if keep != 3 && govRank[r.GovernanceLevel] != 0 {
			t.Fatalf("case %d: removing a policy left %s", i, r.GovernanceLevel)
		}
	}
}

// FZ-03 for the policy input: the re-evaluation is deterministic; the same package gives the identical report across runs.
func TestFZ03_PolicyReevaluationIsDeterministic(t *testing.T) {
	pkg := buildPortableWith(t, false, [32]byte{7}, "outcome-vk", nil, nil)
	first, _ := json.Marshal(Verify(context.Background(), pkg, Options{}))
	if !strings.Contains(string(first), `"policyReevaluations"`) {
		t.Fatalf("the report carries no re-evaluation: %s", first)
	}
	for i := 0; i < 20; i++ {
		again, _ := json.Marshal(Verify(context.Background(), pkg, Options{}))
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, again)
		}
	}
}
