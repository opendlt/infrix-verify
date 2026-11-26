// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package consensus verifies that a Directory block header was certified by the Directory's CometBFT validators: more than 2/3 of the voting power signed
// (ed25519) a commit for that header's hash, and that validator set was reached from a set PINNED in the verifier, one verified transition at a time.
//
// It is CometBFT's light-client rule (light/verifier.go, types/validation.go, v0.38) re-implemented on the standard library and crypto/ed25519, with three
// declared differences, each stricter:
//   - every non-absent signature in a commit is verified, not only enough to cross the threshold (CometBFT's VerifyCommit, not VerifyCommitLight);
//   - a commit signature's validator address must be the address of the validator at its index (CometBFT's index lookup does not compare it);
//   - a non-adjacent step needs more than 2/3 of the trusted set's power, not CometBFT's default 1/3 trust level.
//
// The verifier never reads a trust root from a proof: the Pin is the verifier's own (compiled in, or supplied explicitly by the relying party).
package consensus

import (
	"github.com/opendlt/infrix-verify/l0proof/internal/hexb"
)

// Bytes is a byte string, hex in JSON.
type Bytes = hexb.Bytes

// BlockIDFlag says how a validator voted in a commit (types/block.go).
type BlockIDFlag uint8

const (
	BlockIDFlagAbsent BlockIDFlag = 1 // no vote received
	BlockIDFlagCommit BlockIDFlag = 2 // voted for the commit's block
	BlockIDFlagNil    BlockIDFlag = 3 // voted for nil
)

// precommitType is cmtproto.PrecommitType, the vote type every commit signature signs.
const precommitType = 2

// blockProtocol is version.BlockProtocol, which Header.ValidateBasic requires.
const blockProtocol = 11

// zeroTimeSeconds is the Unix second of Go's zero time, which is how CometBFT encodes an absent vote's timestamp.
const zeroTimeSeconds = -62135596800

// Timestamp is a UTC instant as google.protobuf.Timestamp carries it.
type Timestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

func (t Timestamp) isZeroTime() bool { return t.Seconds == zeroTimeSeconds && t.Nanos == 0 }

func (t Timestamp) after(u Timestamp) bool {
	return t.Seconds > u.Seconds || (t.Seconds == u.Seconds && t.Nanos > u.Nanos)
}

// Version is cometbft.version.v1.Consensus.
type Version struct {
	Block uint64 `json:"block"`
	App   uint64 `json:"app"`
}

// PartSetHeader is types.PartSetHeader.
type PartSetHeader struct {
	Total uint32 `json:"total"`
	Hash  Bytes  `json:"hash"`
}

// BlockID is types.BlockID.
type BlockID struct {
	Hash          Bytes         `json:"hash"`
	PartSetHeader PartSetHeader `json:"partSetHeader"`
}

func (id BlockID) isZero() bool {
	return len(id.Hash) == 0 && id.PartSetHeader.Total == 0 && len(id.PartSetHeader.Hash) == 0
}

// Header is types.Header, every field of which is covered by its hash.
type Header struct {
	Version            Version   `json:"version"`
	ChainID            string    `json:"chainId"`
	Height             int64     `json:"height"`
	Time               Timestamp `json:"time"`
	LastBlockID        BlockID   `json:"lastBlockId"`
	LastCommitHash     Bytes     `json:"lastCommitHash"`
	DataHash           Bytes     `json:"dataHash"`
	ValidatorsHash     Bytes     `json:"validatorsHash"`
	NextValidatorsHash Bytes     `json:"nextValidatorsHash"`
	ConsensusHash      Bytes     `json:"consensusHash"`
	AppHash            Bytes     `json:"appHash"`
	LastResultsHash    Bytes     `json:"lastResultsHash"`
	EvidenceHash       Bytes     `json:"evidenceHash"`
	ProposerAddress    Bytes     `json:"proposerAddress"`
}

// CommitSig is types.CommitSig.
type CommitSig struct {
	BlockIDFlag      BlockIDFlag `json:"blockIdFlag"`
	ValidatorAddress Bytes       `json:"validatorAddress"`
	Timestamp        Timestamp   `json:"timestamp"`
	Signature        Bytes       `json:"signature"`
}

// Commit is types.Commit.
type Commit struct {
	Height     int64       `json:"height"`
	Round      int32       `json:"round"`
	BlockID    BlockID     `json:"blockId"`
	Signatures []CommitSig `json:"signatures"`
}

// Validator is an ed25519 validator and its voting power. The proposer priority is not part of any hash, so it is not carried.
type Validator struct {
	PubKey      Bytes `json:"pubKey"`
	VotingPower int64 `json:"votingPower"`
}

// ValidatorSet is a validator set in CometBFT's canonical order (voting power descending, then address ascending), which its hash and every commit's
// signature indices follow.
type ValidatorSet struct {
	Validators []Validator `json:"validators"`
}

// LightBlock is one step of a consensus trace: a header, the commit that certifies it, the validator set that signed it, and the set that signs the next
// height (which carries trust to the following step).
type LightBlock struct {
	Header         Header       `json:"header"`
	Commit         Commit       `json:"commit"`
	Validators     ValidatorSet `json:"validators"`
	NextValidators ValidatorSet `json:"nextValidators"`
}
