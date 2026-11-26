// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	evidence "github.com/opendlt/infrix-schema/evidence"
)

// The per-level source map (native proof plan section 2, brief 28bj row 2): on every bundle of the corpus, every credited level names its
// source, and no level the verifier did not witness is listed.
func TestEveryCreditedLevelNamesItsSource(t *testing.T) {
	root, storage, account, _ := stateFixture()
	withState := func(b *evidence.EvidenceBundle) { b.StorageProofs, b.AccountProofs = storage, account }
	keysOnly := func(b *evidence.EvidenceBundle) { b.StorageProofs = storage }
	unsigned := func(b *evidence.EvidenceBundle) {
		b.ApprovalEvidence = []evidence.ApprovalEvidenceRef{{StageID: "s1", Identity: "acc://approver.acme", Role: "approver", PlanHash: b.ApprovalEvidence[0].PlanHash}}
	}
	cases := []struct {
		name   string
		pkg    *evidence.PortableEvidencePackage
		opts   Options
		tier   string
		source map[string]string
	}{
		{"anchored, signed, offline", buildPortable(t, true), Options{}, "L3/G1",
			map[string]string{"L3": "recomputed", "G0": "recorded", "G1": "recomputed"}},
		{"anchored, signed, live L0", buildPortable(t, true), Options{L0Confirmer: okConfirmer()}, "L4/G1",
			map[string]string{"L3": "recomputed", "L4": "live-query", "G0": "recorded", "G1": "recomputed"}},
		{"anchored, signed, live L0 and external proof", buildPortable(t, true), Options{L0Confirmer: okConfirmer(), ExternalProofConfirmer: okExternalProofConfirmer{}}, "L4/G2",
			map[string]string{"L3": "recomputed", "L4": "live-query", "G0": "recorded", "G1": "recomputed", "G2": "live-query"}},
		{"state proofs, not anchored", buildPortableWith(t, false, root, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) { withState(b) }), Options{}, "L2/G1",
			map[string]string{"L1": "recomputed", "L2": "recomputed", "G0": "recorded", "G1": "recomputed"}},
		{"keys only", buildPortableWith(t, false, root, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) { keysOnly(b) }), Options{}, "L1/G1",
			map[string]string{"L1": "recomputed", "G0": "recorded", "G1": "recomputed"}},
		{"state proofs and anchored", buildPortableWith(t, true, root, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) { withState(b) }), Options{}, "L3/G1",
			map[string]string{"L1": "recomputed", "L2": "recomputed", "L3": "recomputed", "G0": "recorded", "G1": "recomputed"}},
		{"unsigned approval", buildPortableWith(t, true, [32]byte{7}, "outcome-vk", unsigned, nil), Options{}, "L3/G0",
			map[string]string{"L3": "recomputed", "G0": "recorded"}},
	}
	for _, c := range cases {
		r := Verify(context.Background(), c.pkg, c.opts)
		if r.Tier != c.tier || !r.Verified {
			t.Errorf("%s: tier %s verified %v, want a verified %s (%+v)", c.name, r.Tier, r.Verified, c.tier, r.Checks)
			continue
		}
		if !reflect.DeepEqual(r.LevelSources, c.source) {
			t.Errorf("%s: level sources %v, want %v", c.name, r.LevelSources, c.source)
		}
		// the map names the reported levels themselves
		if r.LevelSources[r.ProofLevel] == "" || r.LevelSources[r.GovernanceLevel] == "" {
			t.Errorf("%s: the reported %s has no source in %v", c.name, r.Tier, r.LevelSources)
		}
	}
}

// Bite: a package whose integrity does not hold is credited nothing, so it names no source; and the map travels in the JSON report.
func TestALevelSourceIsNeverListedForAnUncreditedLevel(t *testing.T) {
	pkg := buildPortable(t, true)
	pkg.OutcomeDigest[0] ^= 1
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})
	if r.ProofLevel != "L0" || r.LevelSources != nil {
		t.Fatalf("a package failing integrity: proof %s, sources %v; want L0 and none", r.ProofLevel, r.LevelSources)
	}
	good := Verify(context.Background(), buildPortable(t, true), Options{})
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		LevelSources map[string]string `json:"levelSources"`
	}
	if err := json.Unmarshal(raw, &back); err != nil || back.LevelSources["L3"] != LevelSourceRecomputed {
		t.Fatalf("the JSON report carries level sources %v (%v)", back.LevelSources, err)
	}
}
