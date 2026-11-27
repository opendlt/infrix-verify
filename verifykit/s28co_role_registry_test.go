// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-schema/policyeval"
)

// s28coVector is infrix-core's shared role registry vector (pkg/role/testdata/role-registry-vector.json, written by the Go encoders).
type s28coVector struct {
	StateRoot      [32]byte                   `json:"stateRoot"`
	Proof          evidence.RoleRegistryProof `json:"proof"`
	Held           map[string][]string        `json:"held"`
	EmptyStateRoot [32]byte                   `json:"emptyStateRoot"`
	EmptyProof     evidence.RoleRegistryProof `json:"emptyProof"`
	EmptyHeld      map[string][]string        `json:"emptyHeld"`
}

func s28coLoad(t *testing.T) s28coVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "role-registry-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v s28coVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// clone deep-copies a proof so a tamper never reaches the vector.
func (v s28coVector) clone(t *testing.T) *evidence.RoleRegistryProof {
	t.Helper()
	raw, err := json.Marshal(v.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var p evidence.RoleRegistryProof
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// THE ROLE REGISTRY PROOF IS RECOMPUTED, AND EVERY TAMPER REFUSES (infrix-core L3112): the vector proves a held record, a record between two
// leaves, one before the first and one after the last, and an empty registry; a changed role set, a non-adjacent bracket, a missing bracket, a
// bracket on the wrong side, another account, an empty claim over a non-empty root, and a proof against another state root each refuse by name.
func TestS28coTheRoleRegistryProofIsRecomputedAndEveryTamperRefuses(t *testing.T) {
	v := s28coLoad(t)
	for _, c := range []struct {
		root  [32]byte
		proof evidence.RoleRegistryProof
		held  map[string][]string
	}{{v.StateRoot, v.Proof, v.Held}, {v.EmptyStateRoot, v.EmptyProof, v.EmptyHeld}} {
		got, err := VerifyRoleRegistryProof(c.root, &c.proof)
		if err != nil {
			t.Fatalf("the vector does not verify: %v", err)
		}
		for h, roles := range c.held {
			if r, ok := got[h]; !ok || strings.Join(r, ",") != strings.Join(roles, ",") {
				t.Fatalf("%s: proven %v (%v); want %v", h, r, ok, roles)
			}
		}
	}
	rec := func(p *evidence.RoleRegistryProof, holder string) *evidence.RoleRecordProof {
		for i := range p.Records {
			if p.Records[i].Holder == holder {
				return &p.Records[i]
			}
		}
		t.Fatalf("the vector has no record of %s", holder)
		return nil
	}
	for name, tamper := range map[string]func(p *evidence.RoleRegistryProof) [32]byte{
		"a held role set changed": func(p *evidence.RoleRegistryProof) [32]byte {
			rec(p, "acc://bob.acme").Held.Roles = []string{"admin", "root"}
			return v.StateRoot
		},
		"a non-adjacent bracket": func(p *evidence.RoleRegistryProof) [32]byte {
			r := rec(p, "acc://carol.acme")
			r.After = rec(p, "acc://zed.acme").Before // frank's leaf, two places after bob's
			return v.StateRoot
		},
		"a missing bracket before the first leaf's successor": func(p *evidence.RoleRegistryProof) [32]byte {
			rec(p, "acc://carol.acme").Before = nil
			return v.StateRoot
		},
		"a bracket on the wrong side": func(p *evidence.RoleRegistryProof) [32]byte {
			r := rec(p, "acc://alice.acme")
			r.Before, r.After = r.After, nil
			return v.StateRoot
		},
		"another account": func(p *evidence.RoleRegistryProof) [32]byte {
			p.Account.Contract = "acc://vector-contract-1.acme"
			return v.StateRoot
		},
		"an empty claim over a non-empty root": func(p *evidence.RoleRegistryProof) [32]byte {
			p.Leaves = 0
			r := rec(p, "acc://zed.acme")
			r.Before = nil
			return v.StateRoot
		},
		"another state root": func(p *evidence.RoleRegistryProof) [32]byte {
			return v.EmptyStateRoot
		},
		"a held record claimed absent": func(p *evidence.RoleRegistryProof) [32]byte {
			r := rec(p, "acc://bob.acme")
			r.Before, r.Held = r.Held, nil
			return v.StateRoot
		},
	} {
		p := v.clone(t)
		root := tamper(p)
		if _, err := VerifyRoleRegistryProof(root, p); err == nil {
			t.Fatalf("%s: the tampered proof verifies", name)
		}
	}
}

// A POLICY THAT READS ACTOR::ROLE IS RE-EVALUATED FROM THE PROVEN REGISTRY (infrix-core L3112): with the bundle's RoleRegistryProof the
// verifier re-runs it and credits G0; without one it cannot (a SKIP, no G0); a proof that does not recompute FAILS; and a policy that denies
// under the proven roles FAILS (the bundle claims a decision the proven state does not reproduce).
func TestS28coAPolicyReadingActorRoleIsReevaluatedFromTheProvenRegistry(t *testing.T) {
	v := s28coLoad(t)
	content, err := policyeval.EncodeDocument(&policyeval.PolicyDocument{ID: "s28co:authorization", Name: "s28co", Type: "authorization", Version: 1,
		DefaultEffect: policyeval.EffectDeny, Rules: []policyeval.DocumentRule{
			{ID: "s28co:admin", Priority: 10, Condition: `actor::role("admin") == 1`, Effect: policyeval.EffectAllow, AuditMsg: "admin", Enabled: true},
		}})
	if err != nil {
		t.Fatal(err)
	}
	bundleFor := func(actor string, proof *evidence.RoleRegistryProof) *evidence.EvidenceBundle {
		return &evidence.EvidenceBundle{StateRoot: v.StateRoot, RoleRegistryProof: proof,
			PolicyDecisions:   []evidence.DecisionProofRef{{PolicyType: "authorization", Decision: "allow", RuleID: "s28co:admin", Actor: actor}},
			PolicyEvaluations: []evidence.PolicyEvaluation{{PolicyType: "authorization", ScopeKey: "global", Policy: evidence.PolicyRef{Hash: policyeval.ContentHash(content), Content: content}, Subject: evidence.PolicySubject{Actor: actor}}}}
	}
	run := func(b *evidence.EvidenceBundle) (bool, *Check) {
		r := &Report{}
		ok := r.checkPolicyReevaluation(b, true, nil, [32]byte{}, Options{})
		for i := range r.Checks {
			if r.Checks[i].Name == "policy_reevaluation" {
				return ok, &r.Checks[i]
			}
		}
		t.Fatal("no policy_reevaluation check")
		return false, nil
	}
	if ok, c := run(bundleFor("acc://bob.acme", v.clone(t))); !ok || c.Status != CheckPass || !strings.Contains(c.Detail, "proven against the bundle's state root") {
		t.Fatalf("a proven admin: %v %+v; want PASS naming the proven registry", ok, c)
	}
	if ok, c := run(bundleFor("acc://bob.acme", nil)); ok || c.Status != CheckSkip {
		t.Fatalf("no role proof: %v %+v; want SKIP", ok, c)
	}
	bad := v.clone(t)
	bad.Records[1].Held.Roles = []string{"admin", "x"}
	if ok, c := run(bundleFor("acc://bob.acme", bad)); ok || c.Status != CheckFail {
		t.Fatalf("a tampered role proof: %v %+v; want FAIL", ok, c)
	}
	if ok, c := run(bundleFor("acc://carol.acme", v.clone(t))); ok || c.Status != CheckFail {
		t.Fatalf("an actor proven to hold no role: %v %+v; want FAIL (the policy denies under the proven roles)", ok, c)
	}
}
