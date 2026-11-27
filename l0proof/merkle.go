// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"crypto/sha256"
	"fmt"
)

// HashSize is the size of every hash an Accumulate receipt or merkle state carries.
const HashSize = 32

// Step is one entry of an Accumulate merkle receipt (pkg/database/merkle ReceiptEntry): the sibling hash, and whether it is combined on the right.
type Step struct {
	Right bool  `json:"right,omitempty"`
	Hash  Bytes `json:"hash"`
}

// Path is the entries of an Accumulate merkle receipt, from the proven value upward. A receipt's Start and Anchor are not carried: the start is always
// computed by the verifier from the content below it, and the anchor is what the path yields, which the next link must then match.
type Path []Step

// combine is merkle.combineHashes (pkg/database/merkle/hash.go): SHA-256 of left then right.
func combine(l, r []byte) []byte {
	h := sha256.New()
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Apply is merkle.Receipt.Validate in its strict form (ValidateOptions.Relaxed false: every entry exactly 32 bytes): it folds the path over start and returns
// the anchor it reaches.
//
// A path carries no positions, and needs none for soundness on Accumulate: every 64-byte preimage on a proof route is a pair of hashes the protocol computed,
// because the executor refuses a transaction body of exactly 64 bytes (internal/core/execute/v2/block/msg_transaction.go) and refuses the single-hash
// AccumulateDataEntry (internal/core/execute/v2/chain/write_data.go entryIsAccepted), the only entry whose hash is SHA-256 of caller-chosen bytes.
func (p Path) Apply(start []byte, maxSteps int) ([]byte, error) {
	if len(start) != HashSize {
		return nil, fmt.Errorf("the path starts from a %d-byte value, want %d", len(start), HashSize)
	}
	if len(p) > maxSteps {
		return nil, fmt.Errorf("the path has %d steps, over the limit of %d", len(p), maxSteps)
	}
	cur := start
	for i, s := range p {
		if len(s.Hash) != HashSize {
			return nil, fmt.Errorf("step %d: the hash is %d bytes, want %d", i, len(s.Hash), HashSize)
		}
		if s.Right {
			cur = combine(cur, s.Hash)
		} else {
			cur = combine(s.Hash, cur)
		}
	}
	return cur, nil
}

// MerkleRoot is merkle.Hasher.MerkleHash (pkg/database/merkle/hasher.go): 32 zero bytes for an empty list, otherwise each hash added to a merkle state
// (State.AddEntry) and the state's anchor (State.Anchor), which folds the pending peaks from the lowest upward, each higher peak on the left.
func MerkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return make([]byte, HashSize)
	}
	var pending [][]byte
	for _, h := range hashes {
		if len(pending) == 0 || pending[len(pending)-1] != nil {
			pending = append(pending, nil)
		}
		for i, v := range pending {
			if v == nil {
				pending[i] = h
				break
			}
			h = combine(v, h)
			pending[i] = nil
		}
	}
	var anchor []byte
	for _, v := range pending {
		if anchor == nil {
			anchor = v
		} else if v != nil {
			anchor = combine(v, anchor)
		}
	}
	return anchor
}
