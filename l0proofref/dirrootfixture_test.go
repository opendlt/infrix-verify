// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/l0proofref/capture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	. "gitlab.com/accumulatenetwork/accumulate/test/harness"
	. "gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
	acctesting "gitlab.com/accumulatenetwork/accumulate/test/testing"
)

// DirRootFixture is the committed SIMULATOR fixture of a key page proven at a Directory-recorded root (govproof directoryroot.go): Proof verifies;
// OtherAnchor is the other partition's anchor proof, which the bites put in Proof's place.
type DirRootFixture struct {
	Proof          govproof.KeyPageProof    `json:"proof"`
	Pin            consensus.Pin            `json:"pin"`
	SignerKeyHash  l0proof.Bytes            `json:"signerKeyHash"`
	OtherPartition string                   `json:"otherPartition"`
	OtherAnchor    govproof.PartitionAnchor `json:"otherAnchor"`
	// Governance is an approval Accumulate executed whose governance page is proven in the directory-root form at the executing block (main's
	// ruling on L3170); LaterPage is the same page proven at a later anchored block, which the bites put in its place.
	Governance govproof.GovernanceExecution   `json:"governance"`
	GovExpect  govproof.GovernanceExpectation `json:"govExpect"`
	LaterPage  govproof.KeyPageProof          `json:"laterPage"`
}

// buildDirectoryRoot runs a two-BVN simulator whose executors retain BPT history: a page signs once on its partition, both partitions go on closing
// blocks, and the page is then proven at the latest BPT root its partition anchored on the Directory, bound by that partition's BlockValidatorAnchor,
// with the Directory hop of the anchor transaction to the current Directory root.
func buildDirectoryRoot(t *testing.T) *DirRootFixture {
	k1 := acctesting.GenerateKey("govproof", "dirroot-approver")
	app := protocol.AccountUrl("govproof-dirroot")
	page := app.JoinPath("book", "1")
	sim := NewSim(t, simulator.SimpleNetwork("govproof-dirroot", 2, 1), simulator.Genesis(GenesisTime), simulator.BPTHistoryDepth(1<<10))
	MakeIdentity(t, sim.DatabaseFor(app), app, k1[32:])
	CreditCredits(t, sim.DatabaseFor(app), page, 1e9)
	da := &protocol.DataAccount{Url: app.JoinPath("data")}
	da.AddAuthority(app.JoinPath("book"))
	MakeAccount(t, sim.DatabaseFor(app), da)
	gda := &protocol.DataAccount{Url: app.JoinPath("governance")}
	gda.AddAuthority(app.JoinPath("book"))
	MakeAccount(t, sim.DatabaseFor(app), gda)
	sim.StepN(5)
	st := sim.BuildAndSubmitTxnSuccessfully(build.Transaction().For(da.Url).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("the page signs once")}}}).
		SignWith(page).Version(1).Timestamp(1).PrivateKey(k1))
	sim.StepUntil(Txn(st.TxID).Succeeds())
	sim.StepN(20)

	partition, err := sim.Router().RouteAccount(page)
	if err != nil || partition == protocol.Directory {
		t.Fatalf("the page must live on a BVN: %v %v", partition, err)
	}
	other := "BVN0"
	if strings.EqualFold(partition, other) {
		other = "BVN1"
	}
	ctx := context.Background()
	txn, anchor, err := capture.LatestPartitionAnchor(ctx, sim.Query(), partition)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := capture.PageAtAnchor(ctx, sim.Query(), page, partition, anchor)
	if err != nil {
		t.Fatal(err)
	}
	pa, dnAnchor, err := capture.AnchorEntry(ctx, sim.Query(), txn)
	if err != nil {
		t.Fatal(err)
	}
	otxn, _, err := capture.LatestPartitionAnchor(ctx, sim.Query(), other)
	if err != nil {
		t.Fatal(err)
	}
	opa, _, err := capture.AnchorEntry(ctx, sim.Query(), otxn)
	if err != nil {
		t.Fatal(err)
	}
	hop, dnBlock, dnRoot, err := capture.DirectoryHop(ctx, sim.Query(), protocol.Directory, dnAnchor, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	keys := capture.Keys("govproof-simulator", 4)
	pin := capture.Pin("simulator", SimChainID, 1, GenesisTime, capture.Set(keys, func(i int) int64 { return 10 }))
	kp.PartitionAnchor, kp.Directory, kp.Consensus, kp.Incarnation = pa, *hop, synthTrace(t, dnRoot, dnBlock, keys, pin), pin.ID()
	kh := l0proof.Bytes(sha256Sum(k1[32:]))

	// an approval Accumulate executes; the network runs on, and the governance page is proven at the executing block through the partition's
	// anchor of exactly that block, then again at a later anchored block
	planHash := sha256.Sum256([]byte("dirroot governance plan"))
	bundleID := "bundle-dirroot-governance"
	payload := govproof.ApprovalPayload(planHash, bundleID)
	gst := sim.BuildAndSubmitTxnSuccessfully(build.Transaction().For(gda.Url).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{payload}}}).
		SignWith(page).Version(1).Timestamp(5).PrivateKey(k1))
	sim.StepUntil(Txn(gst.TxID).Succeeds())
	sim.StepN(20)
	block, err := capture.ExecutedBlock(ctx, sim.Query(), gst.TxID)
	if err != nil {
		t.Fatal(err)
	}
	pageAt := func(block uint64) *govproof.KeyPageProof {
		atx, aa, err := capture.PartitionAnchorAt(ctx, sim.Query(), partition, block)
		if err != nil {
			t.Fatal(err)
		}
		gkp, err := capture.PageAtAnchor(ctx, sim.Query(), page, partition, aa)
		if err != nil {
			t.Fatal(err)
		}
		gpa, gdn, err := capture.AnchorEntry(ctx, sim.Query(), atx)
		if err != nil {
			t.Fatal(err)
		}
		ghop, gdnBlock, gdnRoot, err := capture.DirectoryHop(ctx, sim.Query(), protocol.Directory, gdn, capture.Options{Attempts: 40, Step: sim.Step})
		if err != nil {
			t.Fatal(err)
		}
		gkp.PartitionAnchor, gkp.Directory, gkp.Consensus, gkp.Incarnation = gpa, *ghop, synthTrace(t, gdnRoot, gdnBlock, keys, pin), pin.ID()
		return gkp
	}
	gpage := pageAt(block)
	a, partRoot, err := capture.TxEntry(ctx, sim.Query(), gst.TxID)
	if err != nil {
		t.Fatal(err)
	}
	txHop, txBlock, txRoot, err := capture.DirectoryHop(ctx, sim.Query(), partition, partRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	a.Chain.Directory, a.Chain.Consensus, a.Chain.Incarnation = *txHop, synthTrace(t, txRoot, txBlock, keys, pin), pin.ID()
	sigs, err := capture.Signatures(ctx, sim.Query(), gst.TxID, page)
	if err != nil {
		t.Fatal(err)
	}
	h := gst.TxID.Hash()
	// a later block with activity on the partition, anchored, at which the same page is proven again
	lst := sim.BuildAndSubmitTxnSuccessfully(build.Transaction().For(da.Url).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("a later block")}}}).
		SignWith(page).Version(1).Timestamp(6).PrivateKey(k1))
	sim.StepUntil(Txn(lst.TxID).Succeeds())
	sim.StepN(20)
	lblock, err := capture.ExecutedBlock(ctx, sim.Query(), lst.TxID)
	if err != nil {
		t.Fatal(err)
	}
	return &DirRootFixture{Proof: *kp, Pin: pin, SignerKeyHash: kh, OtherPartition: other, OtherAnchor: *opa,
		Governance: govproof.GovernanceExecution{TxHash: h[:], Signatures: sigs, Receipt: a.Chain, Page: *gpage, ExecutedBlock: block},
		GovExpect:  govproof.GovernanceExpectation{Account: gda.Url.String(), Page: page.String(), PlanHash: planHash, BundleID: bundleID},
		LaterPage:  *pageAt(lblock)}
}

// TestSimulatorDirectoryRootFixture builds a fresh simulator page-at-a-Directory-recorded-root proof and requires it to verify with its height
// proven by the partition's anchor and its block time named unproven, every run. With GOVPROOF_WRITE_FIXTURES=1 it also writes the committed fixture.
func TestSimulatorDirectoryRootFixture(t *testing.T) {
	f := buildDirectoryRoot(t)
	r := govproof.VerifyKeyPage(&f.Proof, l0proof.Options{OverridePin: &f.Pin})
	if !r.Verified {
		t.Fatalf("the simulator directory-root proof does not verify: %s", r.Reason)
	}
	if r.Form != govproof.FormDirectoryRoot || r.Height != f.Proof.Height || r.HeightProvenBy != govproof.HeightByPartitionAnchor || r.BlockTime != 0 ||
		len(r.Unproven) != 1 || r.Unproven[0] != govproof.UnprovenBlockTime || !r.Page.Has(f.SignerKeyHash) {
		t.Fatalf("the verdict claims other than the proof: %+v", r)
	}
	if gr := govproof.VerifyGovernance(&f.Governance, f.GovExpect, l0proof.Options{OverridePin: &f.Pin}); !gr.Verified || gr.Height != f.Governance.ExecutedBlock {
		t.Fatalf("the governance execution with its page at a Directory-recorded root does not verify at its executing block: %+v", gr)
	}
	if os.Getenv("GOVPROOF_WRITE_FIXTURES") != "1" {
		return
	}
	enc := func(v any) []byte {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	files := map[string][]byte{
		"directory-root.json": enc(f),
		"directory-root-provenance.json": enc(map[string]string{
			"source":  "the in-process Accumulate simulator (gitlab.com/Jason_Gregoire/accumulate test/simulator), two BVNs retaining BPT history: a page signs once, both partitions close blocks, and the page is proven from its historical state proof at the latest BPT root its partition anchored on the Directory, bound by the partition's BlockValidatorAnchor on the Directory anchor pool's main chain; Directory headers synthesized over the real Directory BPT root and signed by validator keys derived from the label govproof-simulator",
			"label":   "SIMULATOR fixture: verified only against its own pin passed explicitly; never a Kermit claim",
			"command": "cd l0proofref && GOVPROOF_WRITE_FIXTURES=1 go test -count=1 -run TestSimulatorDirectoryRootFixture .",
		}),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(govDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
