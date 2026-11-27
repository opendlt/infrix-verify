// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtmath "github.com/cometbft/cometbft/libs/math"
	"github.com/cometbft/cometbft/light"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/l0proofref/capture"
)

// DF-02: l0proof/consensus agrees with CometBFT v0.38.0-rc3 (the version Kermit runs; test-only here) on the header hash, the validator-set hash, the vote
// sign bytes, and the verdict of a light-client step, over randomised valid and invalid inputs and over the captured Kermit and simulator headers.
//
// The reference verdict is CometBFT's light step (light.VerifyAdjacent or light.VerifyNonAdjacent at a 2/3 trust level) AND CometBFT's full
// types.VerifyCommit over the untrusted set AND every signature naming its index's validator: the three declared strictness differences of package
// consensus, expressed in CometBFT's own terms.

var trustTwoThirds = cmtmath.Fraction{Numerator: 2, Denominator: 3}

const df02Chain = "DF02.Directory"

func randBytes(r *rand.Rand, n int) []byte { b := make([]byte, n); r.Read(b); return b }

func randHeader(r *rand.Rand) *cmttypes.Header {
	h := &cmttypes.Header{
		ChainID: fmt.Sprintf("chain-%d", r.Intn(1000)), Height: 1 + r.Int63n(1<<40),
		Time:           time.Unix(r.Int63n(1<<33), r.Int63n(1e9)).UTC(),
		LastBlockID:    cmttypes.BlockID{Hash: randBytes(r, 32), PartSetHeader: cmttypes.PartSetHeader{Total: uint32(r.Intn(100)), Hash: randBytes(r, 32)}},
		LastCommitHash: randBytes(r, 32), DataHash: randBytes(r, 32), ValidatorsHash: randBytes(r, 32), NextValidatorsHash: randBytes(r, 32),
		ConsensusHash: randBytes(r, 32), AppHash: randBytes(r, 32), LastResultsHash: randBytes(r, 32), EvidenceHash: randBytes(r, 32),
		ProposerAddress: randBytes(r, 20),
	}
	h.Version.Block, h.Version.App = 11, uint64(r.Intn(5))
	if r.Intn(4) == 0 {
		h.DataHash, h.EvidenceHash, h.LastBlockID = nil, nil, cmttypes.BlockID{}
	}
	return h
}

func randSigners(r *rand.Rand, n int) []capture.Signer {
	out := make([]capture.Signer, n)
	for i := range out {
		out[i] = capture.Signer{Priv: cmted25519.GenPrivKeyFromSecret(randBytes(r, 32))}
	}
	return out
}

func TestDF02_EncodingsAgreeWithCometBFT(t *testing.T) {
	r := rand.New(rand.NewSource(26112026))
	for i := 0; i < 1000; i++ {
		h := randHeader(r)
		mine := capture.Header(h)
		if !bytes.Equal(mine.Hash(), h.Hash()) {
			t.Fatalf("header %d hash disagrees", i)
		}
	}
	for i := 0; i < 500; i++ {
		vs := capture.Set(randSigners(r, 1+r.Intn(20)), func(int) int64 { return 1 + r.Int63n(1000) })
		mine := capture.Validators(vs)
		if !bytes.Equal(mine.Hash(), vs.Hash()) {
			t.Fatalf("validator set %d hash disagrees", i)
		}
	}
	for i := 0; i < 1000; i++ {
		c := &cmttypes.Commit{Height: 1 + r.Int63n(1<<40), Round: int32(r.Intn(3)),
			BlockID: cmttypes.BlockID{Hash: randBytes(r, 32), PartSetHeader: cmttypes.PartSetHeader{Total: uint32(1 + r.Intn(9)), Hash: randBytes(r, 32)}}}
		for k := 1 + r.Intn(6); k > 0; k-- {
			flag := cmttypes.BlockIDFlag(1 + r.Intn(3))
			s := cmttypes.CommitSig{BlockIDFlag: flag}
			if flag != cmttypes.BlockIDFlagAbsent {
				s.ValidatorAddress, s.Timestamp, s.Signature = randBytes(r, 20), time.Unix(r.Int63n(1<<33), r.Int63n(1e9)).UTC(), randBytes(r, 64)
			}
			c.Signatures = append(c.Signatures, s)
		}
		mine := capture.Commit(c)
		chainID := fmt.Sprintf("chain-%d", r.Intn(1000))
		for k := range c.Signatures {
			if !bytes.Equal(mine.VoteSignBytes(chainID, k), c.VoteSignBytes(chainID, int32(k))) {
				t.Fatalf("commit %d signature %d sign bytes disagree", i, k)
			}
		}
	}
}

// reference is CometBFT's verdict on one step from a trusted state (height th, time tt, next validators tnext), with the declared strictness.
func reference(chainID string, th int64, tt time.Time, tnext *cmttypes.ValidatorSet, sh *cmttypes.SignedHeader, vals *cmttypes.ValidatorSet) error {
	trusted := &cmttypes.SignedHeader{Header: &cmttypes.Header{ChainID: chainID, Height: th, Time: tt, NextValidatorsHash: tnext.Hash()}}
	now, period, drift := sh.Time.Add(time.Second), 100*365*24*time.Hour, 10*time.Second
	var err error
	if sh.Height == th+1 {
		err = light.VerifyAdjacent(trusted, sh, vals, period, now, drift)
	} else {
		err = light.VerifyNonAdjacent(trusted, tnext, sh, vals, period, now, drift, trustTwoThirds)
	}
	if err != nil {
		return err
	}
	if err := cmttypes.VerifyCommit(chainID, vals, sh.Commit.BlockID, sh.Height, sh.Commit); err != nil {
		return err
	}
	for i, s := range sh.Commit.Signatures {
		if s.BlockIDFlag != cmttypes.BlockIDFlagAbsent && !bytes.Equal(s.ValidatorAddress, vals.Validators[i].Address) {
			return fmt.Errorf("signature %d names another validator", i)
		}
	}
	return nil
}

func TestDF02_LightStepsAgreeWithCometBFT(t *testing.T) {
	r := rand.New(rand.NewSource(1126))
	genesis := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	agreeOK, agreeBad := 0, 0
	for i := 0; i < 2000; i++ {
		trustedKeys := randSigners(r, 1+r.Intn(8))
		tnext := capture.Set(trustedKeys, func(int) int64 { return 1 + r.Int63n(50) })
		signKeys := trustedKeys
		if r.Intn(3) == 0 { // a rotation: some trusted validators leave, some join
			signKeys = append(append([]capture.Signer{}, trustedKeys[r.Intn(len(trustedKeys)):]...), randSigners(r, 1+r.Intn(3))...)
		}
		vals := capture.Set(signKeys, func(int) int64 { return 1 + r.Int63n(50) })
		th := int64(10 + r.Intn(100))
		h := th + 1
		if r.Intn(2) == 0 {
			h = th + 2 + int64(r.Intn(1000))
		}
		if h == th+1 && r.Intn(2) == 0 {
			vals = tnext // an adjacent step normally keeps the named set
			signKeys = trustedKeys
		}
		at := genesis.Add(time.Duration(h) * time.Second)
		sh := capture.SignedBlock(df02Chain, h, at, randBytes(r, 32), vals, vals, signKeys, fmt.Sprint(i))
		// one invalid-input class, or none
		switch r.Intn(7) {
		case 0:
			k := r.Intn(len(sh.Commit.Signatures))
			sh.Commit.Signatures[k].Signature[r.Intn(64)] ^= 1
		case 1:
			for k := range sh.Commit.Signatures {
				if r.Intn(2) == 0 {
					sh.Commit.Signatures[k] = cmttypes.NewCommitSigAbsent()
				}
			}
		case 2:
			sh.Header.AppHash = randBytes(r, 32) // the commit no longer binds this header
		case 3:
			k := r.Intn(len(sh.Commit.Signatures))
			sh.Commit.Signatures[k].ValidatorAddress = randBytes(r, 20)
		case 4:
			k := r.Intn(len(sh.Commit.Signatures))
			sh.Commit.Signatures[k].BlockIDFlag = cmttypes.BlockIDFlagNil // a nil vote over the block's sign bytes does not verify
		}
		ref := reference(df02Chain, th, genesis.Add(time.Duration(th)*time.Second), tnext, sh, vals)
		pin := consensus.Pin{Network: "df02", ChainID: df02Chain, InitialHeight: th + 1, GenesisTime: capture.Timestamp(genesis.Add(time.Duration(th) * time.Second)), Validators: capture.Validators(tnext)}
		_, mine := consensus.VerifyTrace(&pin, []consensus.LightBlock{capture.LightBlock(sh, vals, vals)}, consensus.DefaultLimits)
		if (ref == nil) != (mine == nil) {
			t.Fatalf("step %d (height %d from %d): CometBFT says %v, l0proof says %v", i, h, th, ref, mine)
		}
		if ref == nil {
			agreeOK++
		} else {
			agreeBad++
		}
	}
	if agreeOK < 300 || agreeBad < 300 {
		t.Fatalf("the randomised steps are lopsided (%d accepted, %d refused); both verdicts must be exercised", agreeOK, agreeBad)
	}
	t.Logf("2000 light steps agree with CometBFT (%d accepted, %d refused)", agreeOK, agreeBad)
}

func toCmtTime(ts consensus.Timestamp) time.Time { return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC() }

func toCmtBlockID(id consensus.BlockID) cmttypes.BlockID {
	return cmttypes.BlockID{Hash: []byte(id.Hash), PartSetHeader: cmttypes.PartSetHeader{Total: id.PartSetHeader.Total, Hash: []byte(id.PartSetHeader.Hash)}}
}

func toCmtSet(t *testing.T, vs consensus.ValidatorSet) *cmttypes.ValidatorSet {
	var vals []*cmttypes.Validator
	for _, v := range vs.Validators {
		vals = append(vals, cmttypes.NewValidator(cmted25519.PubKey(v.PubKey), v.VotingPower))
	}
	return cmttypes.NewValidatorSet(vals)
}

func toCmtSigned(lb consensus.LightBlock) *cmttypes.SignedHeader {
	h := lb.Header
	hdr := &cmttypes.Header{ChainID: h.ChainID, Height: h.Height, Time: toCmtTime(h.Time), LastBlockID: toCmtBlockID(h.LastBlockID),
		LastCommitHash: []byte(h.LastCommitHash), DataHash: []byte(h.DataHash), ValidatorsHash: []byte(h.ValidatorsHash), NextValidatorsHash: []byte(h.NextValidatorsHash),
		ConsensusHash: []byte(h.ConsensusHash), AppHash: []byte(h.AppHash), LastResultsHash: []byte(h.LastResultsHash), EvidenceHash: []byte(h.EvidenceHash),
		ProposerAddress: []byte(h.ProposerAddress)}
	hdr.Version.Block, hdr.Version.App = h.Version.Block, h.Version.App
	c := &cmttypes.Commit{Height: lb.Commit.Height, Round: lb.Commit.Round, BlockID: toCmtBlockID(lb.Commit.BlockID)}
	for _, s := range lb.Commit.Signatures {
		cs := cmttypes.CommitSig{BlockIDFlag: cmttypes.BlockIDFlag(s.BlockIDFlag), ValidatorAddress: []byte(s.ValidatorAddress), Signature: s.Signature}
		if s.BlockIDFlag != consensus.BlockIDFlagAbsent {
			cs.Timestamp = toCmtTime(s.Timestamp)
		}
		c.Signatures = append(c.Signatures, cs)
	}
	return &cmttypes.SignedHeader{Header: hdr, Commit: c}
}

// DF-02 on the captured headers: CometBFT's own light client accepts every step of the Kermit and simulator traces from the same trust roots l0proof
// uses, and the hashes it computes are the ones l0proof computed.
func TestDF02_CometBFTAcceptsTheCapturedTraces(t *testing.T) {
	kpin, _ := l0proof.CompiledPin(l0proof.NetworkKermit)
	var spin consensus.Pin
	b, err := os.ReadFile(filepath.Join(simDir, "pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &spin); err != nil {
		t.Fatal(err)
	}
	for name, pin := range map[string]consensus.Pin{"kermit": kpin, "simulator": spin} {
		raw, err := os.ReadFile(filepath.Join("..", "l0proof", "testdata", name, "chain.json"))
		if err != nil {
			t.Fatal(err)
		}
		var c l0proof.L0ProofChain
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		th, tt, tnext := pin.InitialHeight-1, toCmtTime(pin.GenesisTime).Add(-time.Second), toCmtSet(t, pin.Validators)
		for i, lb := range c.Consensus {
			sh := toCmtSigned(lb)
			if !bytes.Equal(sh.Hash(), lb.Header.Hash()) || !bytes.Equal(sh.Commit.BlockID.Hash, sh.Hash()) {
				t.Fatalf("%s step %d: CometBFT computes another header hash", name, i)
			}
			vals := toCmtSet(t, lb.Validators)
			if err := reference(pin.ChainID, th, tt, tnext, sh, vals); err != nil {
				t.Fatalf("%s step %d: CometBFT refuses a captured step: %v", name, i, err)
			}
			th, tt, tnext = sh.Height, sh.Time, toCmtSet(t, lb.NextValidators)
		}
	}
}

// DF-02 bite: the comparison is not vacuous. A commit whose last signature is forged after more than 2/3 already signed is accepted by CometBFT's
// light-only VerifyCommitLight, but refused by the strict reference and by l0proof; and a commit with every signature valid is accepted by all three.
func TestDF02_TheStrictReferenceBitesWhereTheLightCheckDoesNot(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	keys := randSigners(r, 4)
	vals := capture.Set(keys, func(int) int64 { return 10 })
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	sh := capture.SignedBlock(df02Chain, 5, at, randBytes(r, 32), vals, vals, keys, "bite")
	pin := consensus.Pin{Network: "df02", ChainID: df02Chain, InitialHeight: 5, GenesisTime: capture.Timestamp(at.Add(-time.Second)), Validators: capture.Validators(vals)}
	if err := reference(df02Chain, 4, at.Add(-time.Second), vals, sh, vals); err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.VerifyTrace(&pin, []consensus.LightBlock{capture.LightBlock(sh, vals, vals)}, consensus.DefaultLimits); err != nil {
		t.Fatal(err)
	}
	sh.Commit.Signatures[3].Signature[0] ^= 1
	if err := vals.VerifyCommitLight(df02Chain, sh.Commit.BlockID, 5, sh.Commit); err != nil {
		t.Fatalf("premise: the light-only check should stop before the forged signature: %v", err)
	}
	if reference(df02Chain, 4, at.Add(-time.Second), vals, sh, vals) == nil {
		t.Fatal("the strict reference accepted a forged signature")
	}
	if _, err := consensus.VerifyTrace(&pin, []consensus.LightBlock{capture.LightBlock(sh, vals, vals)}, consensus.DefaultLimits); err == nil {
		t.Fatal("l0proof accepted a forged signature after the threshold")
	}
}
