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
	"testing"
	"time"

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

// govDir is where the SIMULATOR governance fixture lives: labelled as a simulator fixture, verified only against its own pin passed explicitly, never a
// Kermit claim.
var govDir = filepath.Join("..", "govproof", "testdata", "simulator")

// GovFixture is the committed governance fixture.
type GovFixture struct {
	Execution govproof.GovernanceExecution   `json:"execution"`
	Expect    govproof.GovernanceExpectation `json:"expect"`
	Pin       consensus.Pin                  `json:"pin"`
	Signers   []l0proof.Bytes                `json:"signerPublicKeys"`
	Outsider  l0proof.Bytes                  `json:"outsiderSignature"` // a valid signature over the tx by a key NOT on the page
	OtherPage govproof.KeyPageProof          `json:"otherPage"`
	LaterPage govproof.KeyPageProof          `json:"laterPage"`
}

// synthTrace signs a two-block Directory trace from the pin whose last header carries the Directory root as its AppHash. The first block rotates the set to
// one that keeps only half of the genesis power, so the target cannot be trusted from the pin without the first step (every step of the trace is needed).
func synthTrace(t *testing.T, root [32]byte, dnBlock uint64, v0 []capture.Signer, pin consensus.Pin) []consensus.LightBlock {
	v1 := append(append([]capture.Signer{}, v0[2:]...), capture.Keys("govproof-simulator-rotated", 2)...)
	set0 := capture.Set(v0, func(i int) int64 { return 10 })
	set1 := capture.Set(v1, func(i int) int64 { return int64(10 + i) })
	keys := append(append([]capture.Signer{}, v0...), v1[2:]...)
	target := int64(dnBlock) + 1
	if target <= 3 {
		t.Fatalf("the Directory block %d is too early for the synthesized trace", dnBlock)
	}
	at := func(h int64) time.Time { return GenesisTime.Add(time.Duration(h) * time.Second) }
	filler := sha256.Sum256([]byte("an earlier Directory root"))
	b2 := capture.SignedBlock(SimChainID, 2, at(2), filler[:], set0, set1, keys, "gov")
	bt := capture.SignedBlock(SimChainID, target, at(target), root[:], set1, set1, keys, "gov")
	return []consensus.LightBlock{capture.LightBlock(b2, set0, set1), capture.LightBlock(bt, set1, set1)}
}

// buildGovernance runs the simulator: an app identity whose governance page holds three keys with an accept threshold of two, a governance data account,
// and an M-of-N WriteData of the approval payload signed by two of the keys, which Accumulate's executor accepts and executes. The page is captured AT
// EXECUTION TIME (before the partition's next block) and both the transaction and the page are carried to the Directory.
func buildGovernance(t *testing.T) *GovFixture {
	k1 := acctesting.GenerateKey("govproof", "approver-1")
	k2 := acctesting.GenerateKey("govproof", "approver-2")
	k3 := acctesting.GenerateKey("govproof", "approver-3")
	outsider := acctesting.GenerateKey("govproof", "outsider")
	app := protocol.AccountUrl("govproof-app")
	page := app.JoinPath("book", "1")
	data := app.JoinPath("governance")

	sim := NewSim(t, simulator.SimpleNetwork("govproof", 1, 1), simulator.Genesis(GenesisTime))
	MakeIdentity(t, sim.DatabaseFor(app), app, k1[32:], k2[32:], k3[32:])
	UpdateAccount(t, sim.DatabaseFor(app), page, func(p *protocol.KeyPage) { p.AcceptThreshold = 2 })
	CreditCredits(t, sim.DatabaseFor(app), page, 1e9)
	da := &protocol.DataAccount{Url: data}
	da.AddAuthority(app.JoinPath("book"))
	MakeAccount(t, sim.DatabaseFor(app), da)
	other := protocol.AccountUrl("govproof-other")
	otherPage := other.JoinPath("book", "1")
	MakeIdentity(t, sim.DatabaseFor(other), other, outsider[32:])
	CreditCredits(t, sim.DatabaseFor(other), otherPage, 1e9)
	oda := &protocol.DataAccount{Url: other.JoinPath("data")}
	oda.AddAuthority(other.JoinPath("book"))
	MakeAccount(t, sim.DatabaseFor(other), oda)
	sim.StepN(5)
	// the other page signs once, so it has a signature chain like any page in use
	ost := sim.BuildAndSubmitTxnSuccessfully(build.Transaction().For(oda.Url).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("other page in use")}}}).
		SignWith(otherPage).Version(1).Timestamp(1).PrivateKey(outsider))
	sim.StepUntil(Txn(ost.TxID).Succeeds())
	if p2, _ := sim.Router().RouteAccount(otherPage); p2 != func() string { p, _ := sim.Router().RouteAccount(data); return p }() {
		t.Fatalf("the other page must share the governance partition")
	}

	partition, err := sim.Router().RouteAccount(data)
	if err != nil || partition == protocol.Directory {
		t.Fatalf("the governance account must live on a BVN: %v %v", partition, err)
	}

	planHash := sha256.Sum256([]byte("govproof simulator plan"))
	bundleID := "bundle-govproof-simulator"
	payload := govproof.ApprovalPayload(planHash, bundleID)
	env := build.Transaction().For(data).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{payload}}}).
		SignWith(page).Version(1).Timestamp(1).PrivateKey(k1).
		SignWith(page).Version(1).Timestamp(2).PrivateKey(k2)
	st := sim.BuildAndSubmitTxnSuccessfully(env)
	sim.StepUntil(Txn(st.TxID).Succeeds())

	ctx := context.Background()
	// execution time: the page and the ledger, in the BPT root of the block that executed the transaction
	kp, bptRoot, _, err := capture.PageAtBlock(ctx, sim.Query(), page, partition)
	if err != nil {
		t.Fatal(err)
	}
	okp, obptRoot, _, err := capture.PageAtBlock(ctx, sim.Query(), otherPage, partition)
	if err != nil {
		t.Fatal(err)
	}
	if string(obptRoot) != string(bptRoot) {
		t.Fatal("the other page was not read in the executing block's BPT root")
	}
	a, partRoot, err := capture.TxEntry(ctx, sim.Query(), st.TxID)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := capture.Signatures(ctx, sim.Query(), st.TxID, page)
	if err != nil {
		t.Fatal(err)
	}
	txHop, txBlock, txRoot, err := capture.DirectoryHop(ctx, sim.Query(), partition, partRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	pageHop, pageBlock, pageRoot, err := capture.DirectoryHopVia(ctx, sim.Query(), partition, "bpt", bptRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}

	keys := capture.Keys("govproof-simulator", 4)
	pin := capture.Pin("simulator", SimChainID, 1, GenesisTime, capture.Set(keys, func(i int) int64 { return 10 }))
	a.Chain.Directory = *txHop
	a.Chain.Consensus = synthTrace(t, txRoot, txBlock, keys, pin)
	a.Chain.Incarnation = pin.ID()
	kp.Directory = *pageHop
	kp.Consensus = synthTrace(t, pageRoot, pageBlock, keys, pin)
	kp.Incarnation = pin.ID()
	okp.Directory, okp.Consensus, okp.Incarnation = kp.Directory, kp.Consensus, kp.Incarnation

	// a later block: another approval executes, and the governance page is captured after it
	later := build.Transaction().For(data).
		Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{govproof.ApprovalPayload(sha256.Sum256([]byte("a later plan")), "bundle-later")}}}).
		SignWith(page).Version(1).Timestamp(10).PrivateKey(k1).
		SignWith(page).Version(1).Timestamp(11).PrivateKey(k3)
	st2 := sim.BuildAndSubmitTxnSuccessfully(later)
	sim.StepUntil(Txn(st2.TxID).Succeeds())
	lkp, lbptRoot, _, err := capture.PageAtBlock(ctx, sim.Query(), page, partition)
	if err != nil {
		t.Fatal(err)
	}
	lHop, lBlock, lRoot, err := capture.DirectoryHopVia(ctx, sim.Query(), partition, "bpt", lbptRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	lkp.Directory, lkp.Consensus, lkp.Incarnation = *lHop, synthTrace(t, lRoot, lBlock, keys, pin), pin.ID()

	// a valid signature over the same transaction by a key that is not on the page
	out := &protocol.ED25519Signature{PublicKey: outsider[32:], Signer: page, SignerVersion: 1, Timestamp: 3}
	txHash := st.TxID.Hash()
	protocol.SignED25519(out, outsider, nil, txHash[:])
	outBin, err := out.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &GovFixture{
		Execution: govproof.GovernanceExecution{TxHash: txHash[:], Signatures: sigs, Receipt: a.Chain, Page: *kp},
		Expect:    govproof.GovernanceExpectation{Account: data.String(), Page: page.String(), PlanHash: planHash, BundleID: bundleID},
		Pin:       pin,
		Signers:   []l0proof.Bytes{l0proof.Bytes(k1[32:]), l0proof.Bytes(k2[32:]), l0proof.Bytes(k3[32:])},
		Outsider:  outBin,
		OtherPage: *okp,
		LaterPage: *lkp,
	}
}

// TestSimulatorGovernanceFixture builds a fresh simulator governance execution and requires it to verify, every run. With GOVPROOF_WRITE_FIXTURES=1 it
// also writes it as the committed simulator fixture (the simulator's block timing is not bit-for-bit reproducible, so the committed fixture is a captured
// artifact that govproof's own tests verify).
func TestSimulatorGovernanceFixture(t *testing.T) {
	f := buildGovernance(t)
	res := govproof.VerifyGovernance(&f.Execution, f.Expect, l0proof.Options{OverridePin: &f.Pin})
	if !res.Verified {
		t.Fatalf("the simulator governance execution does not verify: %s", res.Reason)
	}
	if res.Signers != 2 || res.Threshold != 2 {
		t.Fatalf("signers %d threshold %d, want 2 and 2", res.Signers, res.Threshold)
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
		"governance.json": enc(f),
		"provenance.json": enc(map[string]string{
			"source":  "the in-process Accumulate simulator (gitlab.com/Jason_Gregoire/accumulate test/simulator), one BVN: a 2-of-3 governance page, a multi-signature WriteData of infrix:approval:v1 || planHash || bundleID that the executor accepted, the page captured at the executing block; Directory headers synthesized over the real Directory BPT roots and signed by validator keys derived from the label govproof-simulator",
			"label":   "SIMULATOR fixture: verified only against its own pin passed explicitly; never a Kermit claim",
			"command": "cd l0proofref && GOVPROOF_WRITE_FIXTURES=1 go test -count=1 -run TestSimulatorGovernanceFixture .",
		}),
	}
	if err := os.MkdirAll(govDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(govDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
