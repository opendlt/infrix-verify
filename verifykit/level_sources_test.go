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
// source, no level the verifier did not witness is listed, and no source is a field the node set.
func TestEveryCreditedLevelNamesItsSource(t *testing.T) {
	root, storage, account, _ := stateFixture()
	withState := func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.StorageProofs, b.AccountProofs = storage, account
	}
	cases := []struct {
		name   string
		pkg    *evidence.PortableEvidencePackage
		opts   Options
		tier   string
		source map[string]string
	}{
		{"anchored, signed, no key-page proof, offline", buildPortable(t, true), Options{}, "L3/G0",
			map[string]string{"L3": "recomputed", "G0": "recomputed"}},
		{"anchored, live L0", buildPortable(t, true), Options{L0Confirmer: okConfirmer()}, "L4/G0",
			map[string]string{"L3": "recomputed", "L4": "live-query", "G0": "recomputed"}},
		{"state proofs, not anchored", buildPortableWith(t, false, root, "outcome-vk", nil, withState), Options{}, "L2/G0",
			map[string]string{"L1": "recomputed", "L2": "recomputed", "G0": "recomputed"}},
		{"state proofs and anchored", buildPortableWith(t, true, root, "outcome-vk", nil, withState), Options{}, "L3/G0",
			map[string]string{"L1": "recomputed", "L2": "recomputed", "L3": "recomputed", "G0": "recomputed"}},
		{"Accumulate-proven (embedded chain, key pages, executed approval)", accPackage(t, nil), accOpts(t), "L4/G2",
			map[string]string{"L3": "recomputed", "L4": "embedded-proof", "G0": "recomputed", "G1": "embedded-proof", "G2": "embedded-proof"}},
		{"key pages proven, no Accumulate transaction", accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) { b.L0Proof, b.GovernanceExecution = nil, nil }), accOpts(t), "L3/G1",
			map[string]string{"L3": "recomputed", "G0": "recomputed", "G1": "embedded-proof"}},
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

// Bites: a package whose integrity does not hold is credited nothing, so it names no source; a bundle whose policies are not re-evaluable
// names no governance source; and the map travels in the JSON report.
func TestALevelSourceIsNeverListedForAnUncreditedLevel(t *testing.T) {
	pkg := buildPortable(t, true)
	pkg.OutcomeDigest[0] ^= 1
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})
	if r.ProofLevel != "L0" || r.LevelSources != nil {
		t.Fatalf("a package failing integrity: proof %s, sources %v; want L0 and none", r.ProofLevel, r.LevelSources)
	}
	noPolicy := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", func(b *evidence.EvidenceBundle) { b.PolicyEvaluations = nil }, nil), Options{})
	if noPolicy.GovernanceLevel != "ungoverned" || noPolicy.LevelSources["G0"] != "" {
		t.Fatalf("a bundle with no re-evaluable policy: %s, sources %v", noPolicy.GovernanceLevel, noPolicy.LevelSources)
	}
	good := Verify(context.Background(), buildPortable(t, true), Options{})
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		LevelSources map[string]string `json:"levelSources"`
	}
	if err := json.Unmarshal(raw, &back); err != nil || back.LevelSources["L3"] != LevelSourceRecomputed || back.LevelSources["G0"] != LevelSourceRecomputed {
		t.Fatalf("the JSON report carries level sources %v (%v)", back.LevelSources, err)
	}
}
