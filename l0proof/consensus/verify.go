// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// maxTotalVotingPower is types.MaxTotalVotingPower: CometBFT caps a set's total at MaxInt64/8 so 2/3 arithmetic cannot overflow.
const maxTotalVotingPower = math.MaxInt64 / 8

// maxChainIDLen is types.MaxChainIDLen.
const maxChainIDLen = 50

// Limits bound a consensus trace. A trace over a limit is refused by name, never truncated.
type Limits struct {
	MaxSteps      int // light blocks in one trace
	MaxValidators int // validators in one set
}

// DefaultLimits are the declared bounds for a Directory trace: a Directory has a handful of validators, and a trace needs a step only per validator-set
// change it crosses.
var DefaultLimits = Limits{MaxSteps: 64, MaxValidators: 150}

// Address is a validator's address: the first 20 bytes of SHA-256 of its ed25519 key (crypto/ed25519 PubKey.Address).
func Address(pubKey []byte) []byte {
	h := sha256.Sum256(pubKey)
	return h[:20]
}

// Hash is Header.Hash (types/block.go): the merkle root of the header's fields, each in its protobuf encoding. A header with no validators hash has no hash,
// as in CometBFT.
func (h *Header) Hash() []byte {
	if len(h.ValidatorsHash) == 0 {
		return nil
	}
	var ver []byte
	ver = appendVarint(ver, 1, h.Version.Block)
	ver = appendVarint(ver, 2, h.Version.App)
	return merkleRoot([][]byte{
		ver,
		cdcString(h.ChainID),
		cdcInt64(h.Height),
		encodeTimestamp(h.Time),
		encodeBlockID(h.LastBlockID),
		cdcBytes(h.LastCommitHash),
		cdcBytes(h.DataHash),
		cdcBytes(h.ValidatorsHash),
		cdcBytes(h.NextValidatorsHash),
		cdcBytes(h.ConsensusHash),
		cdcBytes(h.AppHash),
		cdcBytes(h.LastResultsHash),
		cdcBytes(h.EvidenceHash),
		cdcBytes(h.ProposerAddress),
	})
}

// Hash is ValidatorSet.Hash (types/validator_set.go): the merkle root of each validator's SimpleValidator encoding, {pub_key = 1 {ed25519 = 1}, voting_power = 2}.
func (s *ValidatorSet) Hash() []byte {
	items := make([][]byte, len(s.Validators))
	for i, v := range s.Validators {
		pk := appendBytes(nil, 1, v.PubKey)
		var b []byte
		b = appendMessage(b, 1, pk)
		b = appendVarint(b, 2, uint64(v.VotingPower))
		items[i] = b
	}
	return merkleRoot(items)
}

// VoteSignBytes is Commit.VoteSignBytes (types/block.go, types/canonical.go): the length-delimited CanonicalVote a validator signed for signature i.
func (c *Commit) VoteSignBytes(chainID string, i int) []byte {
	s := c.Signatures[i]
	var b []byte
	b = appendVarint(b, 1, precommitType)
	b = appendSfixed64(b, 2, c.Height)
	b = appendSfixed64(b, 3, int64(c.Round))
	// CommitSig.BlockID: a commit vote signs the commit's block ID; a nil or absent vote signs the zero ID, which CanonicalizeBlockID drops.
	if s.BlockIDFlag == BlockIDFlagCommit && !c.BlockID.isZero() {
		b = appendMessage(b, 4, encodeBlockID(c.BlockID))
	}
	b = appendMessage(b, 5, encodeTimestamp(s.Timestamp))
	b = appendBytes(b, 6, []byte(chainID))
	return append(binary.AppendUvarint(nil, uint64(len(b))), b...)
}

func validateHash(name string, h []byte) error {
	if len(h) != 0 && len(h) != 32 {
		return fmt.Errorf("%s is %d bytes, want 32 or empty", name, len(h))
	}
	return nil
}

func validateBlockID(name string, id BlockID) error {
	if err := validateHash(name+" hash", id.Hash); err != nil {
		return err
	}
	return validateHash(name+" part-set hash", id.PartSetHeader.Hash)
}

// validateSet checks a validator set is well formed, within the limit, and in canonical order, and returns its total voting power.
func validateSet(name string, s *ValidatorSet, lim Limits) (int64, error) {
	n := len(s.Validators)
	if n == 0 {
		return 0, fmt.Errorf("%s is empty", name)
	}
	if n > lim.MaxValidators {
		return 0, fmt.Errorf("%s has %d validators, over the limit of %d", name, n, lim.MaxValidators)
	}
	var total int64
	var prevAddr []byte
	var prevPower int64
	for i, v := range s.Validators {
		if len(v.PubKey) != ed25519.PublicKeySize {
			return 0, fmt.Errorf("%s validator %d: the ed25519 key is %d bytes, want 32", name, i, len(v.PubKey))
		}
		if v.VotingPower <= 0 {
			return 0, fmt.Errorf("%s validator %d: voting power %d is not positive", name, i, v.VotingPower)
		}
		total += v.VotingPower
		if total > maxTotalVotingPower {
			return 0, fmt.Errorf("%s: total voting power exceeds %d", name, int64(maxTotalVotingPower))
		}
		addr := Address(v.PubKey)
		if i > 0 && !(v.VotingPower < prevPower || (v.VotingPower == prevPower && bytes.Compare(addr, prevAddr) > 0)) {
			return 0, fmt.Errorf("%s validator %d is out of canonical order (power descending, then address ascending) or repeated", name, i)
		}
		prevAddr, prevPower = addr, v.VotingPower
	}
	return total, nil
}

// validateHeader is Header.ValidateBasic plus the chain-id check SignedHeader.ValidateBasic makes.
func validateHeader(h *Header, chainID string) error {
	if h.Version.Block != blockProtocol {
		return fmt.Errorf("block protocol %d, want %d", h.Version.Block, blockProtocol)
	}
	if len(h.ChainID) > maxChainIDLen {
		return fmt.Errorf("chain id is %d bytes, over %d", len(h.ChainID), maxChainIDLen)
	}
	if h.ChainID != chainID {
		return fmt.Errorf("chain id %q is not the pinned %q", h.ChainID, chainID)
	}
	if h.Height <= 0 {
		return fmt.Errorf("height %d is not positive", h.Height)
	}
	if err := validateBlockID("last block id", h.LastBlockID); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		v    []byte
	}{{"last commit hash", h.LastCommitHash}, {"data hash", h.DataHash}, {"evidence hash", h.EvidenceHash}, {"last results hash", h.LastResultsHash},
		{"consensus hash", h.ConsensusHash}} {
		if err := validateHash(f.name, f.v); err != nil {
			return err
		}
	}
	if len(h.ValidatorsHash) != 32 || len(h.NextValidatorsHash) != 32 {
		return errors.New("the validators hash and next validators hash must be 32 bytes")
	}
	if len(h.ProposerAddress) != 20 {
		return fmt.Errorf("proposer address is %d bytes, want 20", len(h.ProposerAddress))
	}
	return nil
}

// verifyCommit checks the commit certifies header h under vals: CommitSig.ValidateBasic for every signature, every non-absent signature verified under the
// validator at its index (whose address it must name), and more than 2/3 of vals' power voting for the block. It returns the keys of the verified commit
// votes, for the trust check.
func verifyCommit(chainID string, h *Header, c *Commit, vals *ValidatorSet, total int64) ([][]byte, error) {
	if c.Height != h.Height {
		return nil, fmt.Errorf("commit height %d is not header height %d", c.Height, h.Height)
	}
	if c.Round < 0 {
		return nil, fmt.Errorf("commit round %d is negative", c.Round)
	}
	if err := validateBlockID("commit block id", c.BlockID); err != nil {
		return nil, err
	}
	if c.BlockID.isZero() {
		return nil, errors.New("the commit's block id is empty")
	}
	if !bytes.Equal(c.BlockID.Hash, h.Hash()) {
		return nil, fmt.Errorf("the commit is for block %X, not this header (%X)", []byte(c.BlockID.Hash), h.Hash())
	}
	if len(c.Signatures) != len(vals.Validators) {
		return nil, fmt.Errorf("the commit has %d signatures for %d validators", len(c.Signatures), len(vals.Validators))
	}
	var tallied int64
	var voters [][]byte
	for i, s := range c.Signatures {
		switch s.BlockIDFlag {
		case BlockIDFlagAbsent:
			if len(s.ValidatorAddress) != 0 || !s.Timestamp.isZeroTime() || len(s.Signature) != 0 {
				return nil, fmt.Errorf("signature %d is absent but carries an address, timestamp or signature", i)
			}
			continue
		case BlockIDFlagCommit, BlockIDFlagNil:
		default:
			return nil, fmt.Errorf("signature %d has unknown block id flag %d", i, s.BlockIDFlag)
		}
		v := vals.Validators[i]
		if !bytes.Equal(s.ValidatorAddress, Address(v.PubKey)) {
			return nil, fmt.Errorf("signature %d names validator %X, not the validator at index %d", i, []byte(s.ValidatorAddress), i)
		}
		if len(s.Signature) != ed25519.SignatureSize {
			return nil, fmt.Errorf("signature %d is %d bytes, want 64", i, len(s.Signature))
		}
		if !ed25519.Verify(ed25519.PublicKey(v.PubKey), c.VoteSignBytes(chainID, i), s.Signature) {
			return nil, fmt.Errorf("signature %d does not verify", i)
		}
		if s.BlockIDFlag == BlockIDFlagCommit {
			tallied += v.VotingPower
			voters = append(voters, v.PubKey)
		}
	}
	if tallied <= total*2/3 {
		return nil, fmt.Errorf("only %d of %d voting power signed the block; more than 2/3 is required", tallied, total)
	}
	return voters, nil
}

// trusted is the verifier's trust state between steps: the last certified height and time, and the validator set it trusts to sign what follows.
type trusted struct {
	height   int64
	time     Timestamp
	next     *ValidatorSet
	nextHash []byte
	total    int64
	fromPin  bool
}

// StepError names the step of a trace that could not be verified. An unverifiable step ends verification: nothing after it is trusted.
type StepError struct {
	Step   int   // index in the trace
	Height int64 // the step's header height
	Err    error
}

func (e *StepError) Error() string {
	return fmt.Sprintf("consensus step %d (height %d) is unverifiable: %v", e.Step, e.Height, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }

// VerifyTrace verifies a trace of light blocks from the pin, one step at a time, and returns the last block, whose header is then certified. Every step must
// verify; the first that does not is returned as a *StepError and nothing is certified.
func VerifyTrace(pin *Pin, steps []LightBlock, lim Limits) (*LightBlock, error) {
	if pin == nil {
		return nil, errors.New("no pin: the verifier must supply its own trust root")
	}
	total, err := validateSet("the pinned validator set", &pin.Validators, lim)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		return nil, errors.New("the trace is empty: no header is certified")
	}
	if len(steps) > lim.MaxSteps {
		return nil, fmt.Errorf("the trace has %d steps, over the limit of %d", len(steps), lim.MaxSteps)
	}
	t := trusted{height: pin.InitialHeight - 1, time: pin.GenesisTime, next: &pin.Validators, nextHash: pin.Validators.Hash(), total: total, fromPin: true}
	for i := range steps {
		if err := step(pin.ChainID, &t, &steps[i], lim); err != nil {
			return nil, &StepError{Step: i, Height: steps[i].Header.Height, Err: err}
		}
	}
	return &steps[len(steps)-1], nil
}

func step(chainID string, t *trusted, b *LightBlock, lim Limits) error {
	h := &b.Header
	if err := validateHeader(h, chainID); err != nil {
		return err
	}
	if h.Height <= t.height {
		return fmt.Errorf("height %d does not advance past the trusted height %d", h.Height, t.height)
	}
	// light/verifier.go verifyNewHeaderAndVals: the header time must be after the trusted header's; the genesis time itself is allowed for the first
	// block, which CometBFT stamps with the genesis time.
	if !(h.Time.after(t.time) || (t.fromPin && h.Time == t.time)) {
		return errors.New("the header time does not advance past the trusted time")
	}
	total, err := validateSet("the step's validator set", &b.Validators, lim)
	if err != nil {
		return err
	}
	nextTotal, err := validateSet("the step's next validator set", &b.NextValidators, lim)
	if err != nil {
		return err
	}
	if !bytes.Equal(b.Validators.Hash(), h.ValidatorsHash) {
		return errors.New("the validator set does not hash to the header's validators hash")
	}
	if !bytes.Equal(b.NextValidators.Hash(), h.NextValidatorsHash) {
		return errors.New("the next validator set does not hash to the header's next validators hash")
	}
	voters, err := verifyCommit(chainID, h, &b.Commit, &b.Validators, total)
	if err != nil {
		return err
	}
	if h.Height == t.height+1 {
		// light/verifier.go VerifyAdjacent: the signing set must be the set the trusted header named next.
		if !bytes.Equal(h.ValidatorsHash, t.nextHash) {
			return errors.New("an adjacent header's validators are not the set the trusted state names next")
		}
	} else {
		// light/verifier.go VerifyNonAdjacent, at a 2/3 trust level: more than 2/3 of the TRUSTED set's power must be among the verified commit votes.
		var tallied int64
		seen := make(map[string]bool, len(voters))
		for _, key := range voters {
			if seen[string(key)] {
				return fmt.Errorf("validator %X voted twice", Address(key))
			}
			seen[string(key)] = true
			for _, v := range t.next.Validators {
				if bytes.Equal(v.PubKey, key) {
					tallied += v.VotingPower
					break
				}
			}
		}
		if tallied <= t.total*2/3 {
			return fmt.Errorf("only %d of the trusted set's %d voting power signed; the new validator set cannot be trusted", tallied, t.total)
		}
	}
	t.height, t.time, t.next, t.nextHash, t.total, t.fromPin = h.Height, h.Time, &b.NextValidators, h.NextValidatorsHash, nextTotal, false
	return nil
}
