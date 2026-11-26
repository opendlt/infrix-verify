// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package capture assembles an l0proof.L0ProofChain from an Accumulate network's v3 API: the same code runs against Kermit (over JSON-RPC) and against
// the in-process simulator (its own Querier). It is TEST-ONLY tooling: it lives in the reference module, uses Accumulate's own types to read the API,
// and checks every link it builds with Accumulate's implementation before handing it over, so a capture never records a chain that does not verify.
package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opendlt/infrix-verify/l0proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Anchor is the Accumulate half of a chain (everything but consensus), and the Directory block whose BPT root it reached.
type Anchor struct {
	Chain          l0proof.L0ProofChain
	DirectoryBlock uint64   // the Directory block whose state the chain proves; its root is the AppHash of the header at DirectoryBlock+1
	DirectoryRoot  [32]byte // that block's BPT root
	Leaf           []byte   // the data item the transaction carried
	Principal      *url.URL
}

// Options control a capture.
type Options struct {
	// Poll is how long to wait between attempts while the Directory catches up; Attempts bounds them.
	Poll     time.Duration
	Attempts int
	// Step, when set, is called between attempts instead of sleeping (the simulator advances its blocks here).
	Step func()
}

var zero32 = make([]byte, 32)

// TxEntry captures the transaction and its entry path: the API's receipt from the transaction's main-chain entry to its partition's root-chain anchor
// (indexing.ReceiptForChainEntry), which is historical and so can be read at any time after the transaction executed. It returns that root anchor.
func TxEntry(ctx context.Context, q api.Querier2, txid *url.TxID) (*Anchor, []byte, error) {
	rec, err := q.QueryTransaction(ctx, txid, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("query transaction: %w", err)
	}
	txn := rec.Message.Transaction
	body, ok := txn.Body.(*protocol.WriteData)
	if !ok {
		return nil, nil, fmt.Errorf("transaction %v is %v, not WriteData", txid, txn.Body.Type())
	}
	entry, ok := body.Entry.(*protocol.DoubleHashDataEntry)
	if !ok {
		return nil, nil, fmt.Errorf("transaction %v carries a %v entry, not a double-hash entry", txid, body.Entry.Type())
	}
	header, err := txn.Header.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	noEntry := body.Copy()
	noEntry.Entry = nil
	bodyBin, err := noEntry.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	a := &Anchor{Principal: txn.Header.Principal}
	a.Chain.Transaction = l0proof.WriteDataTx{Header: header, Body: bodyBin}
	for _, d := range entry.Data {
		a.Chain.Transaction.Entry = append(a.Chain.Transaction.Entry, append([]byte(nil), d...))
	}
	txHash := txn.GetHash()
	e, err := q.QueryChainEntry(ctx, txn.Header.Principal, &api.ChainQuery{Name: "main", Entry: txHash, IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		return nil, nil, fmt.Errorf("query the main-chain entry: %w", err)
	}
	r := e.Receipt
	if r == nil || !bytes.Equal(r.Start, txHash) || !r.Validate(nil) {
		return nil, nil, errors.New("the main-chain entry receipt is missing, does not start at the transaction, or does not validate")
	}
	a.Chain.EntryPath = path(r.Entries)
	return a, append([]byte(nil), r.Anchor...), nil
}

func path(es []*merkle.ReceiptEntry) l0proof.Path {
	p := make(l0proof.Path, len(es))
	for i, e := range es {
		p[i] = l0proof.Step{Right: e.Right, Hash: append([]byte(nil), e.Hash...)}
	}
	return p
}

// chainAnchors reads the anchor of every chain of an account, in the account's chain order (the order hashChains hashes them).
func chainAnchors(ctx context.Context, q api.Querier2, account *url.URL) ([]string, [][]byte, error) {
	rr, err := q.QueryAccountChains(ctx, account, &api.ChainQuery{})
	if err != nil {
		return nil, nil, fmt.Errorf("query %v chains: %w", account, err)
	}
	names := make([]string, len(rr.Records))
	anchors := make([][]byte, len(rr.Records))
	for i, c := range rr.Records {
		names[i] = c.Name
		if c.Count == 0 {
			anchors[i] = make([]byte, 32)
			continue
		}
		st := &merkle.State{Count: int64(c.Count), Pending: c.State}
		anchors[i] = st.Anchor()
	}
	return names, anchors, nil
}

// accountProof proves the anchor of the named chain is in the account's state in its partition's BPT, from the account's current state receipt. It returns
// the partition BPT root and the block whose state the receipt proves.
func accountProof(ctx context.Context, q api.Querier2, account *url.URL, chain string, anchor []byte) (*l0proof.AccountProof, []byte, uint64, error) {
	names, anchors, err := chainAnchors(ctx, q, account)
	if err != nil {
		return nil, nil, 0, err
	}
	idx := -1
	for i, n := range names {
		if n == chain {
			idx = i
		}
	}
	if idx < 0 {
		return nil, nil, 0, fmt.Errorf("%v has no %s chain", account, chain)
	}
	if !bytes.Equal(anchors[idx], anchor) {
		return nil, nil, 0, fmt.Errorf("%v's %s chain anchor moved (%X, want %X)", account, chain, anchors[idx], anchor)
	}
	rec, err := q.QueryAccount(ctx, account, &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("query %v state: %w", account, err)
	}
	main, err := rec.Account.MarshalBinary()
	if err != nil {
		return nil, nil, 0, err
	}
	r := rec.Receipt
	if r == nil || len(r.Entries) < 2 {
		return nil, nil, 0, fmt.Errorf("%v's state receipt is missing or short", account)
	}
	mainHash := sha256.Sum256(main)
	if !bytes.Equal(r.Start, mainHash[:]) || !r.Validate(nil) {
		return nil, nil, 0, fmt.Errorf("%v's state receipt does not start at its main state or does not validate", account)
	}
	// hashState is [main, secondary, chains, pending]: the receipt from element 0 climbs past element 1 (the secondary state, on the right) and then the
	// pair hash of elements 2 and 3 (on the right). The verifier recomputes both, so the capture checks they match.
	if !r.Entries[0].Right || !r.Entries[1].Right {
		return nil, nil, 0, fmt.Errorf("%v's state receipt is not shaped as element 0 of the account hash", account)
	}
	h := merkle.Hasher(anchors)
	if !bytes.Equal(combine(h.MerkleHash(), zero32), r.Entries[1].Hash) {
		return nil, nil, 0, fmt.Errorf("%v's chains (with no pending transactions) do not reproduce its state receipt; the state moved or is pending", account)
	}
	p := &l0proof.AccountProof{
		MainState:      main,
		SecondaryState: append([]byte(nil), r.Entries[0].Hash...),
		Chain:          idx,
		Pending:        append([]byte(nil), zero32...),
		StatePath:      path(r.Entries[2:]),
	}
	for _, a := range anchors {
		p.Chains = append(p.Chains, a)
	}
	return p, append([]byte(nil), r.Anchor...), r.LocalBlock, nil
}

func combine(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// DirectoryHop carries a partition's root-chain anchor into the Directory's BPT root: it waits for the Directory to record the anchor on its anchor
// ledger (chain anchor(<partition>)-root), then reads the entry's receipt to the CURRENT Directory root-chain anchor (a receipt with a target height),
// and the Directory ledger's chains and state receipt, retrying until all three describe one Directory block.
func DirectoryHop(ctx context.Context, q api.Querier2, partition string, partitionRoot []byte, o Options) (*l0proof.DirectoryHop, uint64, [32]byte, error) {
	anchors := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	ledger := protocol.DnUrl().JoinPath(protocol.Ledger)
	chain := fmt.Sprintf("anchor(%s)-root", strings.ToLower(partition))
	wait := func() {
		if o.Step != nil {
			o.Step()
		} else {
			time.Sleep(o.Poll)
		}
	}
	var lastErr error
	for i := 0; i < o.Attempts; i++ {
		if i > 0 {
			wait()
		}
		names, la, err := chainAnchors(ctx, q, ledger)
		if err != nil {
			lastErr = err
			continue
		}
		rootIdx, rootCount := -1, uint64(0)
		for j, n := range names {
			if n == "root" {
				rootIdx = j
			}
		}
		if rootIdx < 0 {
			return nil, 0, [32]byte{}, errors.New("the Directory ledger has no root chain")
		}
		rr, err := q.QueryAccountChains(ctx, ledger, &api.ChainQuery{})
		if err != nil {
			lastErr = err
			continue
		}
		rootCount = rr.Records[rootIdx].Count
		e, err := q.QueryChainEntry(ctx, anchors, &api.ChainQuery{Name: chain, Entry: partitionRoot, IncludeReceipt: &api.ReceiptOptions{ForAny: true, ForHeight: rootCount - 1}})
		if err != nil {
			lastErr = fmt.Errorf("the Directory has not recorded the partition root on %s yet: %w", chain, err)
			continue
		}
		if e.Receipt == nil || !bytes.Equal(e.Receipt.Start, partitionRoot) || !e.Receipt.Validate(nil) {
			lastErr = errors.New("the Directory entry receipt is missing or invalid")
			continue
		}
		if !bytes.Equal(e.Receipt.Anchor, la[rootIdx]) {
			lastErr = fmt.Errorf("the entry receipt reaches root anchor %X, not the current %X", e.Receipt.Anchor, la[rootIdx])
			continue
		}
		lp, root, block, err := accountProof(ctx, q, ledger, "root", la[rootIdx])
		if err != nil {
			lastErr = err
			continue
		}
		var rb [32]byte
		copy(rb[:], root)
		return &l0proof.DirectoryHop{AnchorPath: path(e.Receipt.Entries), Ledger: *lp}, block, rb, nil
	}
	return nil, 0, [32]byte{}, fmt.Errorf("the Directory hop did not settle in %d attempts: %v", o.Attempts, lastErr)
}
