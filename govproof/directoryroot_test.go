// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/internal/tamper"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// dirRootFixture is the SIMULATOR fixture of a page proven at a Directory-recorded root (testdata/simulator/directory-root.json, written by
// l0proofref TestSimulatorDirectoryRootFixture): verified only against its own pin passed explicitly, never a Kermit claim.
type dirRootFixture struct {
	Proof          govproof.KeyPageProof    `json:"proof"`
	Pin            consensus.Pin            `json:"pin"`
	SignerKeyHash  l0proof.Bytes            `json:"signerKeyHash"`
	OtherPartition string                   `json:"otherPartition"`
	OtherAnchor    govproof.PartitionAnchor `json:"otherAnchor"`
}

func loadDirRoot(t testing.TB) *dirRootFixture {
	b, err := os.ReadFile(filepath.Join("testdata", "simulator", "directory-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f dirRootFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func cloneKP(t testing.TB, p *govproof.KeyPageProof) *govproof.KeyPageProof {
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var c govproof.KeyPageProof
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func mustRefuseKP(t *testing.T, r govproof.KeyPageResult, want string) {
	t.Helper()
	if r.Verified {
		t.Fatalf("verified; want a refusal naming %q", want)
	}
	if !strings.Contains(r.Reason, want) {
		t.Fatalf("refused for %q; want the refusal to name %q", r.Reason, want)
	}
	if r.Height != 0 || r.HeightProvenBy != "" || len(r.Page.KeyHashes) != 0 {
		t.Fatalf("a refused proof credits height %d (%q) and %d keys", r.Height, r.HeightProvenBy, len(r.Page.KeyHashes))
	}
}

// L3168 (a): the page proven at a BPT root its partition anchored on the Directory credits the page's keys, the partition the anchor names and the
// height the anchor states, and names the block time unproven, claiming none.
func TestS28clAPageAtADirectoryRecordedRootCreditsItsKeysAndTheAnchoredHeight(t *testing.T) {
	f := loadDirRoot(t)
	r := govproof.VerifyKeyPage(&f.Proof, l0proof.Options{OverridePin: &f.Pin})
	if !r.Verified {
		t.Fatalf("the directory-root proof does not verify: %s", r.Reason)
	}
	if r.Form != govproof.FormDirectoryRoot || !r.Page.Has(f.SignerKeyHash) || r.Page.AcceptThreshold == 0 {
		t.Fatalf("form %q, keys %d, threshold %d", r.Form, len(r.Page.KeyHashes), r.Page.AcceptThreshold)
	}
	if r.Height != f.Proof.Height || r.HeightProvenBy != govproof.HeightByPartitionAnchor {
		t.Fatalf("height %d proven by %q; want %d proven by the partition anchor", r.Height, r.HeightProvenBy, f.Proof.Height)
	}
	if want := "acc://bvn-" + strings.ToLower(f.Proof.Partition) + ".acme/ledger"; r.Partition != want {
		t.Fatalf("partition %q, want %q", r.Partition, want)
	}
	if r.BlockTime != 0 || r.RootAnchor != nil || !reflect.DeepEqual(r.Unproven, []string{govproof.UnprovenBlockTime}) {
		t.Fatalf("the verdict claims a block time %d or root anchor %X the anchor does not prove (unproven %v)", r.BlockTime, r.RootAnchor, r.Unproven)
	}
}

// Bite: the other partition's anchor transaction in the proof's place refuses, by name, even though it is a real anchor the Directory executed.
func TestS28clAnAnchorNamingAnotherPartitionRefuses(t *testing.T) {
	f := loadDirRoot(t)
	p := cloneKP(t, &f.Proof)
	p.PartitionAnchor = &f.OtherAnchor
	mustRefuseKP(t, govproof.VerifyKeyPage(p, l0proof.Options{OverridePin: &f.Pin}), "the anchor names partition acc://bvn-"+f.OtherPartition+".acme")
	// and relabelling the proof to the other partition does not help: that anchor does not state the page's root
	p.Partition = f.OtherPartition
	mustRefuseKP(t, govproof.VerifyKeyPage(p, l0proof.Options{OverridePin: &f.Pin}), "but the partition's anchor states root")
}

// Bite: a proof with no ledger and no anchor transaction credits no height (and nothing else): neither its partition nor its block is proven.
func TestS28clADirectoryRootProofWithoutTheAnchorTransactionCreditsNoHeight(t *testing.T) {
	f := loadDirRoot(t)
	p := cloneKP(t, &f.Proof)
	p.PartitionAnchor = nil
	mustRefuseKP(t, govproof.VerifyKeyPage(p, l0proof.Options{OverridePin: &f.Pin}), "neither its partition nor its block height is proven")
	p.PartitionAnchor = &govproof.PartitionAnchor{EntryPath: f.Proof.PartitionAnchor.EntryPath}
	mustRefuseKP(t, govproof.VerifyKeyPage(p, l0proof.Options{OverridePin: &f.Pin}), "neither its partition nor its block height is proven")
}

// G2 needs the page at the executing block: a governance execution whose page is a directory-root proof is refused, even when everything else holds.
func TestS28clADirectoryRootPageNeverStandsInForTheExecutingBlock(t *testing.T) {
	g := load(t)
	ex := cloneExec(t, &g.Execution)
	d := loadDirRoot(t)
	ex.Page = *cloneKP(t, &d.Proof)
	r := govproof.VerifyGovernance(ex, g.Expect, l0proof.Options{OverridePin: &d.Pin})
	if r.Verified || !strings.Contains(r.Reason, "not at the block that executed the transaction") {
		t.Fatalf("verified %v (%s); want the directory-root page refused for G2", r.Verified, r.Reason)
	}
}

// TS-ALL for the KeyPageProof TYPE across both forms: every mutation of every field of the directory-root fixture, and of the ledger-form fixture,
// that changes the proof makes it fail, and together they cover every field path of the type.
func TestTSALL_EveryFieldOfBothKeyPageProofFormsIsTamperEvident(t *testing.T) {
	d := loadDirRoot(t)
	g := load(t)
	covered := map[string]bool{}
	total := 0
	for _, c := range []struct {
		proof *govproof.KeyPageProof
		opts  l0proof.Options
	}{{cloneKP(t, &d.Proof), l0proof.Options{OverridePin: &d.Pin}}, {cloneKP(t, &g.Execution.Page), g.opts()}} {
		p := c.proof
		before := cloneKP(t, p)
		if r := govproof.VerifyKeyPage(p, c.opts); !r.Verified {
			t.Fatalf("the fixture does not verify: %s", r.Reason)
		}
		var ms []tamper.Mutation
		tamper.Mutations(reflect.ValueOf(p).Elem(), "", &ms)
		for _, m := range ms {
			m.Apply()
			if !sameKP(t, p, before) {
				if r := govproof.VerifyKeyPage(p, c.opts); r.Verified {
					t.Errorf("%s of %s still verifies", m.Kind, m.Path)
				}
				covered[tamper.TypePath(m.Path)] = true
				total++
			}
			m.Undo()
		}
		if r := govproof.VerifyKeyPage(p, c.opts); !r.Verified {
			t.Fatalf("the restored proof no longer verifies: %s", r.Reason)
		}
	}
	if miss := tamper.Missing(reflect.TypeOf(govproof.KeyPageProof{}), covered); len(miss) > 0 {
		t.Fatalf("the census found %d field(s) with no effective mutation: %s", len(miss), strings.Join(miss, ", "))
	}
	t.Logf("%d mutations over %d field paths, every one refused", total, len(covered))
}

func sameKP(t *testing.T, a, b *govproof.KeyPageProof) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(ja) == string(jb)
}
