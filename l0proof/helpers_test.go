// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// The two committed fixtures. testdata/kermit is a real Kermit capture (an Infrix WriteData, its receipts, the Directory header and commit), verified
// against the COMPILED Kermit pin. testdata/simulator is an in-process Accumulate simulator capture with synthesized Directory headers, verified only
// against its own pin passed explicitly; it is never a Kermit claim.
type fixture struct {
	name  string
	chain *l0proof.L0ProofChain
	exp   l0proof.Expectation
	opts  l0proof.Options
	raw   []byte
}

func readJSON(t testing.TB, path string, v any) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return b
}

func loadFixture(t testing.TB, name string) *fixture {
	t.Helper()
	dir := filepath.Join("testdata", name)
	raw, err := os.ReadFile(filepath.Join(dir, "chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := l0proof.Decode(raw, nil)
	if err != nil {
		t.Fatalf("decode %s chain: %v", name, err)
	}
	var e struct {
		AnchorAccount string        `json:"anchorAccount"`
		Leaf          l0proof.Bytes `json:"leaf"`
	}
	readJSON(t, filepath.Join(dir, "expect.json"), &e)
	f := &fixture{name: name, chain: chain, exp: l0proof.Expectation{AnchorAccount: e.AnchorAccount, Leaf: e.Leaf}, raw: raw}
	if name == "kermit" {
		f.opts = l0proof.Options{Network: l0proof.NetworkKermit}
	} else {
		var pin consensus.Pin
		readJSON(t, filepath.Join(dir, "pin.json"), &pin)
		f.opts = l0proof.Options{OverridePin: &pin}
	}
	return f
}

func fixtures(t testing.TB) []*fixture {
	return []*fixture{loadFixture(t, "kermit"), loadFixture(t, "simulator")}
}

// clone deep-copies a chain through its encoding.
func clone(t testing.TB, c *l0proof.L0ProofChain) *l0proof.L0ProofChain {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	out, err := l0proof.Decode(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustVerify(t testing.TB, f *fixture, c *l0proof.L0ProofChain, exp l0proof.Expectation, opts l0proof.Options) l0proof.Result {
	t.Helper()
	r := l0proof.Verify(c, exp, opts)
	if !r.Verified {
		t.Fatalf("%s: expected the chain to verify: %s", f.name, r.Reason)
	}
	return r
}

func mustFail(t testing.TB, what string, c *l0proof.L0ProofChain, exp l0proof.Expectation, opts l0proof.Options, reasonHas string) l0proof.Result {
	t.Helper()
	r := l0proof.Verify(c, exp, opts)
	if r.Verified {
		t.Fatalf("%s: verified, but must fail", what)
	}
	if r.TxHash != nil || r.DirectoryRoot != nil || r.DirectoryHeight != 0 {
		t.Fatalf("%s: a failed verdict still credits a tx hash, root or height", what)
	}
	if reasonHas != "" && !bytes.Contains([]byte(r.Reason), []byte(reasonHas)) {
		t.Fatalf("%s: the reason %q does not name %q", what, r.Reason, reasonHas)
	}
	return r
}

// --- a tiny CometBFT signer built on l0proof's own encoders, for traces the fixtures do not contain -------------------------------------------------

type signer struct {
	priv  ed25519.PrivateKey
	power int64
}

func keys(label string, n int, power int64) []signer {
	out := make([]signer, n)
	for i := range out {
		seed := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", label, i)))
		out[i] = signer{priv: ed25519.NewKeyFromSeed(seed[:]), power: power}
	}
	return out
}

func pub(s signer) []byte { return s.priv.Public().(ed25519.PublicKey) }

// canonical sorts signers into CometBFT's validator order and returns the set.
func canonical(ss []signer) ([]signer, consensus.ValidatorSet) {
	ss = append([]signer(nil), ss...)
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].power != ss[j].power {
			return ss[i].power > ss[j].power
		}
		return bytes.Compare(consensus.Address(pub(ss[i])), consensus.Address(pub(ss[j]))) < 0
	})
	var vs consensus.ValidatorSet
	for _, s := range ss {
		vs.Validators = append(vs.Validators, consensus.Validator{PubKey: pub(s), VotingPower: s.power})
	}
	return ss, vs
}

// block makes a light block at height h signed by every signer in vals (or only those for which sign returns true).
func block(chainID string, h int64, at consensus.Timestamp, appHash []byte, vals, next []signer, sign func(i int) bool) consensus.LightBlock {
	vs, set := canonical(vals)
	_, nset := canonical(next)
	fill := func(tag string) []byte {
		x := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s", chainID, h, tag)))
		return x[:]
	}
	hdr := consensus.Header{
		Version: consensus.Version{Block: 11}, ChainID: chainID, Height: h, Time: at,
		LastBlockID:    consensus.BlockID{Hash: fill("last"), PartSetHeader: consensus.PartSetHeader{Total: 1, Hash: fill("lastparts")}},
		LastCommitHash: fill("lc"), DataHash: fill("data"), ValidatorsHash: set.Hash(), NextValidatorsHash: nset.Hash(),
		ConsensusHash: fill("cons"), AppHash: appHash, LastResultsHash: fill("res"), EvidenceHash: fill("ev"),
		ProposerAddress: consensus.Address(pub(vs[0])),
	}
	c := consensus.Commit{Height: h, BlockID: consensus.BlockID{Hash: hdr.Hash(), PartSetHeader: consensus.PartSetHeader{Total: 1, Hash: fill("parts")}}}
	for i := range vs {
		if sign != nil && !sign(i) {
			c.Signatures = append(c.Signatures, consensus.CommitSig{BlockIDFlag: consensus.BlockIDFlagAbsent, Timestamp: consensus.Timestamp{Seconds: -62135596800}})
			continue
		}
		c.Signatures = append(c.Signatures, consensus.CommitSig{BlockIDFlag: consensus.BlockIDFlagCommit, ValidatorAddress: consensus.Address(pub(vs[i])),
			Timestamp: consensus.Timestamp{Seconds: at.Seconds, Nanos: int32(i + 1)}})
	}
	for i := range vs {
		if c.Signatures[i].BlockIDFlag == consensus.BlockIDFlagAbsent {
			continue
		}
		c.Signatures[i].Signature = ed25519.Sign(vs[i].priv, c.VoteSignBytes(chainID, i))
	}
	return consensus.LightBlock{Header: hdr, Commit: c, Validators: set, NextValidators: nset}
}

func pinOf(network, chainID string, initial int64, genesis consensus.Timestamp, vals []signer) consensus.Pin {
	_, set := canonical(vals)
	return consensus.Pin{Network: network, ChainID: chainID, InitialHeight: initial, GenesisTime: genesis, Validators: set}
}
