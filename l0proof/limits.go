// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// Limits are the declared bounds of a proof. A proof over any of them is refused by name, never truncated or partly checked.
type Limits struct {
	MaxProofBytes       int // the encoded chain
	MaxPathSteps        int // steps in one receipt path
	MaxTransactionBytes int // header + body, and separately the entry's data
	MaxEntryItems       int // data items in the entry
	MaxMainStateBytes   int // one account's main state
	MaxChains           int // chains of one account
	Consensus           consensus.Limits
}

// DefaultLimits follow Accumulate's own: a transaction is at most protocol.TransactionSizeMax (20480) bytes and an entry at most 100 parts
// (globals.limits.dataEntryParts); a BPT path is at most 256 deep and a chain receipt at most 64; a Directory trace is bounded by consensus.DefaultLimits.
var DefaultLimits = Limits{
	MaxProofBytes:       1 << 22,
	MaxPathSteps:        512,
	MaxTransactionBytes: 20480,
	MaxEntryItems:       100,
	MaxMainStateBytes:   1 << 16,
	MaxChains:           64,
	Consensus:           consensus.DefaultLimits,
}

// ErrProofTooLarge is returned, by name, for an encoded proof over Limits.MaxProofBytes.
var ErrProofTooLarge = errors.New("the L0 proof chain exceeds the size limit (Limits.MaxProofBytes)")

// Decode parses an encoded L0ProofChain. It refuses an encoding over the size limit before reading it, an unknown field, and trailing data.
func Decode(data []byte, lim *Limits) (*L0ProofChain, error) {
	if lim == nil {
		lim = &DefaultLimits
	}
	if len(data) > lim.MaxProofBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrProofTooLarge, len(data), lim.MaxProofBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c L0ProofChain
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode the L0 proof chain: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("decode the L0 proof chain: trailing data after the chain")
	}
	return &c, nil
}
