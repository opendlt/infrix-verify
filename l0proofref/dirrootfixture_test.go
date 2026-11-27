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
	return &DirRootFixture{Proof: *kp, Pin: pin, SignerKeyHash: kh, OtherPartition: other, OtherAnchor: *opa}
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
