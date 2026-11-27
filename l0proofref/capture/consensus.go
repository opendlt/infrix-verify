// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package capture

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// Timestamp converts a time to the wire timestamp.
func Timestamp(t time.Time) consensus.Timestamp {
	t = t.UTC()
	return consensus.Timestamp{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
}

func blockID(id cmttypes.BlockID) consensus.BlockID {
	return consensus.BlockID{Hash: []byte(id.Hash), PartSetHeader: consensus.PartSetHeader{Total: id.PartSetHeader.Total, Hash: []byte(id.PartSetHeader.Hash)}}
}

// Header converts a CometBFT header.
func Header(h *cmttypes.Header) consensus.Header {
	return consensus.Header{
		Version:            consensus.Version{Block: h.Version.Block, App: h.Version.App},
		ChainID:            h.ChainID,
		Height:             h.Height,
		Time:               Timestamp(h.Time),
		LastBlockID:        blockID(h.LastBlockID),
		LastCommitHash:     []byte(h.LastCommitHash),
		DataHash:           []byte(h.DataHash),
		ValidatorsHash:     []byte(h.ValidatorsHash),
		NextValidatorsHash: []byte(h.NextValidatorsHash),
		ConsensusHash:      []byte(h.ConsensusHash),
		AppHash:            []byte(h.AppHash),
		LastResultsHash:    []byte(h.LastResultsHash),
		EvidenceHash:       []byte(h.EvidenceHash),
		ProposerAddress:    []byte(h.ProposerAddress),
	}
}

// Commit converts a CometBFT commit.
func Commit(c *cmttypes.Commit) consensus.Commit {
	out := consensus.Commit{Height: c.Height, Round: c.Round, BlockID: blockID(c.BlockID)}
	for _, s := range c.Signatures {
		out.Signatures = append(out.Signatures, consensus.CommitSig{
			BlockIDFlag:      consensus.BlockIDFlag(s.BlockIDFlag),
			ValidatorAddress: []byte(s.ValidatorAddress),
			Timestamp:        Timestamp(s.Timestamp),
			Signature:        append([]byte(nil), s.Signature...),
		})
	}
	return out
}

// Validators converts a CometBFT validator set (already in canonical order).
func Validators(vs *cmttypes.ValidatorSet) consensus.ValidatorSet {
	var out consensus.ValidatorSet
	for _, v := range vs.Validators {
		out.Validators = append(out.Validators, consensus.Validator{PubKey: append([]byte(nil), v.PubKey.Bytes()...), VotingPower: v.VotingPower})
	}
	return out
}

// LightBlock converts a CometBFT signed header with its validator set and next validator set.
func LightBlock(sh *cmttypes.SignedHeader, vals, next *cmttypes.ValidatorSet) consensus.LightBlock {
	return consensus.LightBlock{Header: Header(sh.Header), Commit: Commit(sh.Commit), Validators: Validators(vals), NextValidators: Validators(next)}
}

// Signer is a validator key held by a synthesized chain (the simulator has no CometBFT, so its Directory headers are signed by keys the test derives).
type Signer struct {
	Priv ed25519.PrivKey
}

// Keys derives n deterministic ed25519 validator keys from a label.
func Keys(label string, n int) []Signer {
	out := make([]Signer, n)
	for i := range out {
		seed := sha256.Sum256([]byte(fmt.Sprintf("%s/validator/%d", label, i)))
		out[i] = Signer{Priv: ed25519.GenPrivKeyFromSecret(seed[:])}
	}
	return out
}

// Set makes a validator set of the signers with the given powers, in CometBFT's canonical order.
func Set(signers []Signer, power func(i int) int64) *cmttypes.ValidatorSet {
	vals := make([]*cmttypes.Validator, len(signers))
	for i, s := range signers {
		vals[i] = cmttypes.NewValidator(s.Priv.PubKey(), power(i))
	}
	return cmttypes.NewValidatorSet(vals)
}

// SignedBlock builds a header at height signed by every signer in vals (looked up by address in keys), with appHash as its AppHash.
func SignedBlock(chainID string, height int64, at time.Time, appHash []byte, vals, next *cmttypes.ValidatorSet, keys []Signer, salt string) *cmttypes.SignedHeader {
	fill := func(tag string) []byte {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%s", chainID, salt, height, tag)))
		return h[:]
	}
	h := &cmttypes.Header{
		ChainID:            chainID,
		Height:             height,
		Time:               at,
		LastBlockID:        cmttypes.BlockID{Hash: fill("last"), PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: fill("lastparts")}},
		LastCommitHash:     fill("lastcommit"),
		DataHash:           fill("data"),
		ValidatorsHash:     vals.Hash(),
		NextValidatorsHash: next.Hash(),
		ConsensusHash:      fill("consensus"),
		AppHash:            appHash,
		LastResultsHash:    fill("results"),
		EvidenceHash:       fill("evidence"),
		ProposerAddress:    vals.Validators[0].Address,
	}
	h.Version.Block = 11
	id := cmttypes.BlockID{Hash: h.Hash(), PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: fill("parts")}}
	c := &cmttypes.Commit{Height: height, Round: 0, BlockID: id}
	for i, v := range vals.Validators {
		var key *Signer
		for j := range keys {
			if string(keys[j].Priv.PubKey().Address()) == string(v.Address) {
				key = &keys[j]
			}
		}
		if key == nil {
			panic("no key for a validator")
		}
		ts := at.Add(time.Duration(i+1) * time.Millisecond)
		vote := &cmttypes.Vote{Type: cmtproto.PrecommitType, Height: height, Round: 0, BlockID: id, Timestamp: ts, ValidatorAddress: v.Address, ValidatorIndex: int32(i)}
		sig, err := key.Priv.Sign(cmttypes.VoteSignBytes(chainID, vote.ToProto()))
		if err != nil {
			panic(err)
		}
		c.Signatures = append(c.Signatures, cmttypes.CommitSig{BlockIDFlag: cmttypes.BlockIDFlagCommit, ValidatorAddress: v.Address, Timestamp: ts, Signature: sig})
	}
	return &cmttypes.SignedHeader{Header: h, Commit: c}
}

// Pin makes a pin from a genesis.
func Pin(network, chainID string, initialHeight int64, genesis time.Time, vals *cmttypes.ValidatorSet) consensus.Pin {
	return consensus.Pin{Network: network, ChainID: chainID, InitialHeight: initialHeight, GenesisTime: Timestamp(genesis), Validators: Validators(vals)}
}
