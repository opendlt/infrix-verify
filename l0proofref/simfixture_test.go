// Copyright 2024 The Infrix Authors
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

// simDir is where the SIMULATOR fixture lives. It is labelled as a simulator fixture everywhere: its pin's network is "simulator", it is never compiled in,
// and it is never a Kermit claim.
var simDir = filepath.Join("..", "l0proof", "testdata", "simulator")

// SimChainID is the chain id the synthesized Directory headers carry. The simulator runs Accumulate's real executors but no CometBFT, so its Directory
// headers are synthesized over its real Directory BPT root and signed by validator keys derived from a label.
const SimChainID = "Simulator.Directory"

// buildSimulatorChain runs the Accumulate simulator: one BVN, an identity with a data account on it, a WriteData carrying leaf, then the anchor round trip
// to the Directory. It captures the chain through the simulator's own v3 API (the same capture code Kermit uses), and synthesizes a three-step Directory
// trace with a validator-set change: height 2 signed by the genesis set and naming a rotated set next, height 3 (adjacent) signed by the rotated set, and
// the target height (non-adjacent) signed by the rotated set.
func buildSimulatorChain(t *testing.T) (*l0proof.L0ProofChain, consensus.Pin, l0proof.Expectation) {
	key := acctesting.GenerateKey("l0proof", "anchor-key")
	alice := protocol.AccountUrl("l0proof-anchor")
	data := alice.JoinPath("anchors")

	sim := NewSim(t, simulator.SimpleNetwork("l0proof", 1, 1), simulator.Genesis(GenesisTime))
	MakeIdentity(t, sim.DatabaseFor(alice), alice, key[32:])
	CreditCredits(t, sim.DatabaseFor(alice), alice.JoinPath("book", "1"), 1e9)
	da := &protocol.DataAccount{Url: data}
	da.AddAuthority(alice.JoinPath("book"))
	MakeAccount(t, sim.DatabaseFor(alice), da)
	sim.StepN(5)

	partition, err := sim.Router().RouteAccount(data)
	if err != nil || partition == protocol.Directory {
		t.Fatalf("the anchor account must live on a BVN: %v %v", partition, err)
	}

	leaf := sha256.Sum256([]byte("l0proof simulator batch root"))
	st := sim.BuildAndSubmitTxnSuccessfully(
		build.Transaction().For(data).
			Body(&protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("infrix-batch-root"), leaf[:]}}}).
			SignWith(alice.JoinPath("book", "1")).Version(1).Timestamp(1).PrivateKey(key))
	// Capture at the block the transaction executed: a BVN anchors the BPT root of a block only when that block carried messages
	// (crosschain.ConstructLastAnchor sends nothing for a block whose ledger has no anchor), so a later idle block's root is never anchored.
	sim.StepUntil(Txn(st.TxID).Succeeds())

	ctx := context.Background()
	a, partRoot, err := capture.TxEntry(ctx, sim.Query(), st.TxID)
	if err != nil {
		t.Fatal(err)
	}
	hop, dnBlock, dnRoot, err := capture.DirectoryHop(ctx, sim.Query(), partition, partRoot, capture.Options{Attempts: 40, Step: sim.Step})
	if err != nil {
		t.Fatal(err)
	}
	a.Chain.Directory = *hop

	v0 := capture.Keys("l0proof-simulator", 4)
	// the rotation keeps only half of the genesis power, so the target cannot be trusted from the pin without the transition step
	v1keys := append(append([]capture.Signer{}, v0[2:]...), capture.Keys("l0proof-simulator-rotated", 2)...)
	set0 := capture.Set(v0, func(i int) int64 { return 10 })
	set1 := capture.Set(v1keys, func(i int) int64 { return int64(10 + i) })
	keys := append(append([]capture.Signer{}, v0...), v1keys[2:]...)
	pin := capture.Pin("simulator", SimChainID, 1, GenesisTime, set0)

	target := int64(dnBlock) + 1
	if target <= 3 {
		t.Fatalf("the Directory block %d is too early for the synthesized trace", dnBlock)
	}
	at := func(h int64) time.Time { return GenesisTime.Add(time.Duration(h) * time.Second) }
	filler := sha256.Sum256([]byte("an earlier Directory root"))
	b2 := capture.SignedBlock(SimChainID, 2, at(2), filler[:], set0, set1, keys, "sim")
	b3 := capture.SignedBlock(SimChainID, 3, at(3), filler[:], set1, set1, keys, "sim")
	bt := capture.SignedBlock(SimChainID, target, at(target), dnRoot[:], set1, set1, keys, "sim")
	a.Chain.Consensus = []consensus.LightBlock{capture.LightBlock(b2, set0, set1), capture.LightBlock(b3, set1, set1), capture.LightBlock(bt, set1, set1)}
	a.Chain.Incarnation = pin.ID()
	return &a.Chain, pin, l0proof.Expectation{AnchorAccount: a.Principal.String(), Leaf: leaf[:]}
}

type expectFile struct {
	AnchorAccount string        `json:"anchorAccount"`
	Leaf          l0proof.Bytes `json:"leaf"`
}

// TestSimulatorFixture builds a fresh simulator chain and requires it to verify, every run. With L0PROOF_WRITE_FIXTURES=1 it also writes it as the
// committed simulator fixture (the simulator's block timing is not bit-for-bit reproducible across runs, so the committed fixture is a captured artifact,
// verified on its own by l0proof's tests, rather than a value this test regenerates).
func TestSimulatorFixture(t *testing.T) {
	chain, pin, exp := buildSimulatorChain(t)
	res := l0proof.Verify(chain, exp, l0proof.Options{OverridePin: &pin})
	if !res.Verified {
		t.Fatalf("the simulator chain does not verify: %s", res.Reason)
	}
	if os.Getenv("L0PROOF_WRITE_FIXTURES") != "1" {
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
		"chain.json":  enc(chain),
		"pin.json":    enc(pin),
		"expect.json": enc(expectFile{AnchorAccount: exp.AnchorAccount, Leaf: exp.Leaf}),
		"provenance.json": enc(map[string]string{
			"source":  "the in-process Accumulate simulator (gitlab.com/Jason_Gregoire/accumulate test/simulator), one BVN; Directory headers synthesized over its real Directory BPT root and signed by validator keys derived from the label l0proof-simulator",
			"label":   "SIMULATOR fixture: verified only against its own pin passed explicitly; never a Kermit claim",
			"command": "cd l0proofref && L0PROOF_WRITE_FIXTURES=1 go test -count=1 -run TestSimulatorFixture .",
		}),
	}
	if err := os.MkdirAll(simDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(simDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
