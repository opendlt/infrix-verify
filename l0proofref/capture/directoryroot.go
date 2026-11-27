// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// THE REFERENCE CAPTURE OF A PAGE AT A DIRECTORY-RECORDED ROOT (govproof directoryroot.go; core KNOWN-LIMITS L3168). The page is proven from the
// network's historical state proof at the block of the latest BPT root its partition anchored on the Directory, and that root is bound to the
// partition by the BlockValidatorAnchor transaction the Directory's anchor pool executed. No partition ledger is read, so a network that serves a
// page's historical proof but not its ledger's still yields the proof.

// LatestPartitionAnchor is the latest BlockValidatorAnchor from partition the Directory executed, read from the end of the anchor pool's main chain.
func LatestPartitionAnchor(ctx context.Context, q api.Querier2, partition string) (*protocol.Transaction, *protocol.BlockValidatorAnchor, error) {
	pool := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	source := protocol.PartitionUrl(partition)
	const page = 64
	for start := uint64(0); ; start += page {
		r, err := q.QueryMainChainEntries(ctx, pool, &api.ChainQuery{Name: "main", Range: &api.RangeOptions{FromEnd: true, Start: start, Count: api.Ptr[uint64](page), Expand: api.Ptr(true)}})
		if err != nil {
			return nil, nil, fmt.Errorf("query the Directory anchor pool's main chain: %w", err)
		}
		for j := len(r.Records) - 1; j >= 0; j-- {
			v := r.Records[j].Value
			if v == nil || v.Message == nil || v.Message.Transaction == nil {
				continue
			}
			a, ok := v.Message.Transaction.Body.(*protocol.BlockValidatorAnchor)
			if ok && a.Source.Equal(source) {
				return v.Message.Transaction, a, nil
			}
		}
		if uint64(len(r.Records)) < page {
			return nil, nil, fmt.Errorf("the Directory has executed no anchor of %s", partition)
		}
	}
}

// AnchorEntry is a partition anchor's PartitionAnchor proof (the transaction's exact binary and its entry path on the anchor pool's main chain) and
// the Directory root-chain anchor the path reaches.
func AnchorEntry(ctx context.Context, q api.Querier2, txn *protocol.Transaction) (*govproof.PartitionAnchor, []byte, error) {
	header, err := txn.Header.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	body, err := txn.Body.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	txHash := txn.GetHash()
	e, err := q.QueryChainEntry(ctx, txn.Header.Principal, &api.ChainQuery{Name: "main", Entry: txHash, IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		return nil, nil, fmt.Errorf("query the anchor's main-chain entry: %w", err)
	}
	r := e.Receipt
	if r == nil || !bytes.Equal(r.Start, txHash) || !r.Validate(nil) {
		return nil, nil, errors.New("the anchor's main-chain entry receipt is missing, does not start at the transaction, or does not validate")
	}
	return &govproof.PartitionAnchor{Transaction: govproof.AnchorTx{Header: header, Body: body}, EntryPath: path(r.Entries)}, append([]byte(nil), r.Anchor...), nil
}

// receiptCut applies a receipt's entries from start and returns how many it takes to reach root, or -1 when it never passes through root.
func receiptCut(start []byte, es []*merkle.ReceiptEntry, root []byte) int {
	h := append([]byte(nil), start...)
	for i, e := range es {
		if e.Right {
			h = combine(h, e.Hash)
		} else {
			h = combine(e.Hash, h)
		}
		if bytes.Equal(h, root) {
			return i + 1
		}
	}
	return -1
}

// indexAtOrBefore is the last entry of an index chain whose block is at or before block, and its position, or nil when the chain had no entry by then.
func indexAtOrBefore(ctx context.Context, q api.Querier2, account *url.URL, name string, block uint64) (*protocol.IndexEntry, uint64, error) {
	const page = 64
	for start := uint64(0); ; start += page {
		r, err := q.QueryIndexChainEntries(ctx, account, &api.ChainQuery{Name: name, Range: &api.RangeOptions{FromEnd: true, Start: start, Count: api.Ptr[uint64](page), Expand: api.Ptr(true)}})
		if err != nil {
			return nil, 0, fmt.Errorf("query %v %s: %w", account, name, err)
		}
		for j := len(r.Records) - 1; j >= 0; j-- {
			v := r.Records[j].Value
			if v == nil || v.Value == nil {
				return nil, 0, fmt.Errorf("%v %s entry %d carries no index entry", account, name, r.Records[j].Index)
			}
			if v.Value.BlockIndex <= block {
				return v.Value, r.Records[j].Index, nil
			}
		}
		if uint64(len(r.Records)) < page {
			return nil, 0, nil
		}
	}
}

// chainAnchorsAt reads the anchor of every chain of account as of the end of block, in the account's chain order. A chain's length at the block is
// read from the index chain: for a chain with an index chain, the last index entry at or before the block names the chain's last element then
// (Source); for an index chain itself, it is the position of its own last entry at or before the block. The anchor is the chain's merkle state at
// that length. A chain with no entry by then has the zero anchor.
func chainAnchorsAt(ctx context.Context, q api.Querier2, account *url.URL, block uint64) ([][]byte, error) {
	rr, err := q.QueryAccountChains(ctx, account, &api.ChainQuery{})
	if err != nil {
		return nil, fmt.Errorf("query %v chains: %w", account, err)
	}
	anchors := make([][]byte, len(rr.Records))
	for i, c := range rr.Records {
		anchors[i] = make([]byte, 32)
		if c.Count == 0 {
			continue
		}
		var last uint64
		if c.Type == merkle.ChainTypeIndex {
			ie, pos, err := indexAtOrBefore(ctx, q, account, c.Name, block)
			if err != nil {
				return nil, err
			}
			if ie == nil {
				continue
			}
			last = pos
		} else {
			ie, _, err := indexAtOrBefore(ctx, q, account, c.Name+"-index", block)
			if err != nil {
				return nil, err
			}
			if ie == nil {
				continue
			}
			last = ie.Source
		}
		e, err := q.QueryChainEntry(ctx, account, &api.ChainQuery{Name: c.Name, Index: api.Ptr(last)})
		if err != nil {
			return nil, fmt.Errorf("%v's %s chain element %d (its last at block %d): %w", account, c.Name, last, block, err)
		}
		st := &merkle.State{Count: int64(last + 1), Pending: e.State}
		anchors[i] = st.Anchor()
	}
	return anchors, nil
}

// PageAtAnchor proves a key page in the BPT root a partition anchor states, from the network's historical state proof at the anchor's minor block. It
// returns the proof without its Directory hop and consensus trace.
func PageAtAnchor(ctx context.Context, q api.Querier2, page *url.URL, partition string, anchor *protocol.BlockValidatorAnchor) (*govproof.KeyPageProof, error) {
	block, root := anchor.MinorBlockIndex, anchor.StateTreeAnchor[:]
	rec, err := q.QueryAccount(ctx, page, &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForHeight: block}})
	if err != nil {
		return nil, fmt.Errorf("%v's historical state proof at block %d: %w", page, block, err)
	}
	r := rec.Receipt
	if r == nil || !r.StartsAtMainState || rec.Account == nil {
		return nil, fmt.Errorf("%v at block %d is answered without a historical receipt from its main state", page, block)
	}
	main, err := rec.Account.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mainHash := sha256.Sum256(main)
	if !bytes.Equal(r.Start, mainHash[:]) || !r.Validate(nil) || len(r.Entries) < 2 || !r.Entries[0].Right || !r.Entries[1].Right {
		return nil, fmt.Errorf("%v's historical receipt at block %d does not start at its main state, is not shaped as the account hash, or does not validate", page, block)
	}
	anchors, err := chainAnchorsAt(ctx, q, page, block)
	if err != nil {
		return nil, err
	}
	h := merkle.Hasher(anchors)
	if !bytes.Equal(combine(h.MerkleHash(), zero32), r.Entries[1].Hash) {
		return nil, fmt.Errorf("%v's chains as of block %d (with no pending transactions) do not reproduce its historical receipt", page, block)
	}
	cut := receiptCut(mainHash[:], r.Entries, root)
	if cut < 3 {
		return nil, fmt.Errorf("%v's historical receipt at block %d does not pass through the anchored BPT root %X", page, block, root)
	}
	pp := l0proof.AccountProof{MainState: main, SecondaryState: append([]byte(nil), r.Entries[0].Hash...), Pending: append([]byte(nil), zero32...),
		StatePath: path(r.Entries[2:cut])}
	for _, a := range anchors {
		pp.Chains = append(pp.Chains, a)
	}
	return &govproof.KeyPageProof{Page: page.String(), Height: block, Partition: partition, PageState: pp}, nil
}

// PartitionAnchorAt is the BlockValidatorAnchor from partition the Directory executed for exactly minor block block.
func PartitionAnchorAt(ctx context.Context, q api.Querier2, partition string, block uint64) (*protocol.Transaction, *protocol.BlockValidatorAnchor, error) {
	pool := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	source := protocol.PartitionUrl(partition)
	const page = 64
	for start := uint64(0); ; start += page {
		r, err := q.QueryMainChainEntries(ctx, pool, &api.ChainQuery{Name: "main", Range: &api.RangeOptions{FromEnd: true, Start: start, Count: api.Ptr[uint64](page), Expand: api.Ptr(true)}})
		if err != nil {
			return nil, nil, fmt.Errorf("query the Directory anchor pool's main chain: %w", err)
		}
		for j := len(r.Records) - 1; j >= 0; j-- {
			v := r.Records[j].Value
			if v == nil || v.Message == nil || v.Message.Transaction == nil {
				continue
			}
			if a, ok := v.Message.Transaction.Body.(*protocol.BlockValidatorAnchor); ok && a.Source.Equal(source) && a.MinorBlockIndex == block {
				return v.Message.Transaction, a, nil
			}
		}
		if uint64(len(r.Records)) < page {
			return nil, nil, fmt.Errorf("the Directory has executed no anchor of %s for block %d", partition, block)
		}
	}
}

// ExecutedBlock is the partition block that executed txid: the block of its main-chain entry receipt.
func ExecutedBlock(ctx context.Context, q api.Querier2, txid *url.TxID) (uint64, error) {
	h := txid.Hash()
	e, err := q.QueryChainEntry(ctx, txid.Account(), &api.ChainQuery{Name: "main", Entry: h[:], IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil || e.Receipt == nil {
		return 0, fmt.Errorf("the main-chain entry receipt of %v: %v", txid, err)
	}
	return e.Receipt.LocalBlock, nil
}
