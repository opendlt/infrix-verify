// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/l0proofref/capture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	. "gitlab.com/accumulatenetwork/accumulate/test/harness"
	. "gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
)

// accDir is verifykit's Accumulate-proven bundle fixture (verifykit/accumulate_proofs_test.go describes the two steps). SIMULATOR-labelled.
var accDir = filepath.Join("..", "verifykit", "testdata", "accumulate")

type accTarget struct {
	BatchRoot string   `json:"batchRoot"`
	PlanHash  string   `json:"planHash"`
	BundleID  string   `json:"bundleId"`
	Page      string   `json:"page"`
	Account   string   `json:"account"`
	Seeds     []string `json:"seeds"`
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAccumulateBundleProofs is step 2: the simulator anchors the target's batch root as the single data item of a WriteData, executes the M-of-N
// approval of its plan for its bundle under the 2-of-3 page, captures the page AT EXECUTION TIME, and carries all three to the Directory. Every run
// verifies what it built; with GOVPROOF_WRITE_FIXTURES=1 it writes proofs.json.
func TestAccumulateBundleProofs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(accDir, "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tg accTarget
	if err := json.Unmarshal(raw, &tg); err != nil {
		t.Fatal(err)
	}
	var keys []ed25519.PrivateKey
	var pubs [][]byte
	for _, s := range tg.Seeds {
		k := ed25519.NewKeyFromSeed(unhex(t, s))
		keys = append(keys, k)
		pubs = append(pubs, k[32:])
	}
	page, err := url.Parse(tg.Page)
	if err != nil {
		t.Fatal(err)
	}
	account, err := url.Parse(tg.Account)
	if err != nil {
		t.Fatal(err)
	}
	app := page.Identity().Identity()
	anchors := app.JoinPath("anchors")

	sim := NewSim(t, simulator.SimpleNetwork("infrix-vk", 1, 1), simulator.Genesis(GenesisTime))
	MakeIdentity(t, sim.DatabaseFor(app), app, pubs...)
	UpdateAccount(t, sim.DatabaseFor(app), page, func(p *protocol.KeyPage) { p.AcceptThreshold = 2 })
	CreditCredits(t, sim.DatabaseFor(app), page, 1e9)
	for _, u := range []*url.URL{account, anchors} {
		da := &protocol.DataAccount{Url: u}
		da.AddAuthority(app.JoinPath("book"))
		MakeAccount(t, sim.DatabaseFor(app), da)
	}
	sim.StepN(5)
	partition, err := sim.Router().RouteAccount(account)
	if err != nil || partition == protocol.Directory {
		t.Fatalf("the accounts must live on a BVN: %v %v", partition, err)
	}

	submit := func(to *url.URL, item []byte, ts uint64) *protocol.TransactionStatus {
		st := sim.BuildAndSubmitTxnSuccessfully(build.Transaction().For(to).
			Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{item}}}).
			SignWith(page).Version(1).Timestamp(ts).PrivateKey(keys[0]).
			SignWith(page).Version(1).Timestamp(ts + 1).PrivateKey(keys[1]))
		sim.StepUntil(Txn(st.TxID).Succeeds())
		return st
	}
	ctx := context.Background()
	v0 := capture.Keys("infrix-vk-simulator", 4)
	pin := capture.Pin("simulator", SimChainID, 1, GenesisTime, capture.Set(v0, func(i int) int64 { return 10 }))
	toDirectory := func(c *l0proof.L0ProofChain, partRoot []byte) {
		hop, block, root, err := capture.DirectoryHop(ctx, sim.Query(), partition, partRoot, capture.Options{Attempts: 40, Step: sim.Step})
		if err != nil {
			t.Fatal(err)
		}
		c.Directory, c.Consensus, c.Incarnation = *hop, synthTrace(t, root, block, v0, pin), pin.ID()
	}

	// the batch root, as its own data item (the leaf binding l0proof requires)
	var batchRoot [32]byte
	copy(batchRoot[:], unhex(t, tg.BatchRoot))
	ast := submit(anchors, batchRoot[:], 1)
	a, partRoot, err := capture.TxEntry(ctx, sim.Query(), ast.TxID)
	if err != nil {
		t.Fatal(err)
	}
	toDirectory(&a.Chain, partRoot)

	// the M-of-N approval of the plan for the bundle, the page captured at its executing block
	var planHash [32]byte
	copy(planHash[:], unhex(t, tg.PlanHash))
	gst := submit(account, govproof.ApprovalPayload(planHash, tg.BundleID), 3)
	kp, bptRoot, _, err := capture.PageAtBlock(ctx, sim.Query(), page, partition)
	if err != nil {
		t.Fatal(err)
	}
	g, gRoot, err := capture.TxEntry(ctx, sim.Query(), gst.TxID)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := capture.Signatures(ctx, sim.Query(), gst.TxID, page)
	if err != nil {
		t.Fatal(err)
	}
	toDirectory(&g.Chain, gRoot)
	hop, block, root, err := capture.DirectoryHopVia(ctx, sim.Query(), partition, "bpt", bptRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	kp.Directory, kp.Consensus, kp.Incarnation = *hop, synthTrace(t, root, block, v0, pin), pin.ID()
	gHash := gst.TxID.Hash()
	exec := govproof.GovernanceExecution{TxHash: gHash[:], Signatures: sigs, Receipt: g.Chain, Page: *kp}

	opts := l0proof.Options{OverridePin: &pin}
	if r := l0proof.Verify(&a.Chain, l0proof.Expectation{AnchorAccount: anchors.String(), Leaf: batchRoot[:]}, opts); !r.Verified {
		t.Fatalf("the batch-root chain does not verify: %s", r.Reason)
	}
	if r := govproof.VerifyGovernance(&exec, govproof.GovernanceExpectation{Account: account.String(), Page: page.String(), PlanHash: planHash, BundleID: tg.BundleID}, opts); !r.Verified {
		t.Fatalf("the governance execution does not verify: %s", r.Reason)
	}
	if os.Getenv("GOVPROOF_WRITE_FIXTURES") != "1" {
		return
	}
	enc := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	out := struct {
		L0Proof             json.RawMessage   `json:"l0Proof"`
		KeyPageProofs       []json.RawMessage `json:"keyPageProofs"`
		GovernanceExecution json.RawMessage   `json:"governanceExecution"`
		Pin                 consensus.Pin     `json:"pin"`
		Provenance          map[string]string `json:"provenance"`
	}{enc(a.Chain), []json.RawMessage{enc(kp)}, enc(exec), pin, map[string]string{
		"source":  "the in-process Accumulate simulator (gitlab.com/Jason_Gregoire/accumulate test/simulator), one BVN: the target bundle's batch root written as the single data item of a WriteData, and the M-of-N approval of its plan for its bundle executed under a 2-of-3 page captured at the executing block; Directory headers synthesized over the real Directory BPT roots and signed by validator keys derived from the label infrix-vk-simulator",
		"label":   "SIMULATOR fixture: verified only against its own pin passed explicitly; never a Kermit claim",
		"command": "cd l0proofref && GOVPROOF_WRITE_FIXTURES=1 go test -count=1 -run TestAccumulateBundleProofs .",
	}}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accDir, "proofs.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
