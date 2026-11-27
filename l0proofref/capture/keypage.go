// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// accountAt proves an account's state, naming the chain index the proof hands up ("" for the account's first chain), from the account's CURRENT state receipt. It returns the proof, the BPT
// root and the block the receipt proves.
func accountAt(ctx context.Context, q api.Querier2, account *url.URL, chain string) (*l0proof.AccountProof, []byte, uint64, error) {
	names, anchors, err := chainAnchors(ctx, q, account)
	if err != nil {
		return nil, nil, 0, err
	}
	for i, n := range names {
		if n == chain || (chain == "" && i == 0) {
			return accountProof(ctx, q, account, n, anchors[i])
		}
	}
	return nil, nil, 0, fmt.Errorf("%v has no %s chain", account, chain)
}

// PageAtBlock captures the page and the partition ledger in ONE partition BPT root: the state right after the governed block. It must run in the window
// before the partition's next block (the ledger changes every block), which is why the node captures at execution time; Kermit serves no historical BPT
// proof. It returns the proof without its Directory hop, the BPT root and the block.
func PageAtBlock(ctx context.Context, q api.Querier2, page *url.URL, partition string) (*govproof.KeyPageProof, []byte, uint64, error) {
	ledgerURL := protocol.PartitionUrl(partition).JoinPath(protocol.Ledger)
	pp, proot, pblock, err := accountAt(ctx, q, page, "")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("page: %w", err)
	}
	lp, lroot, lblock, err := accountAt(ctx, q, ledgerURL, "root")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ledger: %w", err)
	}
	if !bytes.Equal(proot, lroot) || pblock != lblock {
		return nil, nil, 0, fmt.Errorf("the page (block %d) and the ledger (block %d) were read from different BPT roots", pblock, lblock)
	}
	kp := &govproof.KeyPageProof{Page: page.String(), Height: pblock, PageState: *pp, LedgerState: *lp}
	return kp, proot, pblock, nil
}

// DirectoryHopVia is DirectoryHop for any of the Directory's anchor chains of a partition: "root" for a root-chain anchor (what DirectoryHop does) or "bpt"
// for a BPT root (a key-page proof).
func DirectoryHopVia(ctx context.Context, q api.Querier2, partition, kind string, value []byte, o Options) (*l0proof.DirectoryHop, uint64, [32]byte, error) {
	if kind != "root" && kind != "bpt" {
		return nil, 0, [32]byte{}, fmt.Errorf("unknown anchor chain kind %q", kind)
	}
	anchors := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	ledger := protocol.DnUrl().JoinPath(protocol.Ledger)
	chain := fmt.Sprintf("anchor(%s)-%s", strings.ToLower(partition), kind)
	var lastErr error
	for i := 0; i < o.Attempts; i++ {
		if i > 0 {
			if o.Step != nil {
				o.Step()
			} else {
				time.Sleep(o.Poll)
			}
		}
		names, la, err := chainAnchors(ctx, q, ledger)
		if err != nil {
			lastErr = err
			continue
		}
		rootIdx := -1
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
		rootCount := rr.Records[rootIdx].Count
		e, err := q.QueryChainEntry(ctx, anchors, &api.ChainQuery{Name: chain, Entry: value, IncludeReceipt: &api.ReceiptOptions{ForAny: true, ForHeight: rootCount - 1}})
		if err != nil {
			lastErr = fmt.Errorf("the Directory has not recorded %X on %s yet: %w", value, chain, err)
			continue
		}
		if e.Receipt == nil || !bytes.Equal(e.Receipt.Start, value) || !e.Receipt.Validate(nil) {
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
	return nil, 0, [32]byte{}, fmt.Errorf("the Directory hop via %s did not settle in %d attempts: %v", chain, o.Attempts, lastErr)
}

// Signatures reads the ED25519 signatures the network recorded for a transaction from the page, in their exact binary, in the canonical order
// govproof requires (ascending bytes).
func Signatures(ctx context.Context, q api.Querier2, txid *url.TxID, page *url.URL) ([]l0proof.Bytes, error) {
	rec, err := q.QueryTransaction(ctx, txid, nil)
	if err != nil {
		return nil, err
	}
	var out []l0proof.Bytes
	seen := map[string]bool{}
	if rec.Signatures == nil {
		return nil, errors.New("the transaction record carries no signatures")
	}
	for _, set := range rec.Signatures.Records {
		if set.Signatures == nil {
			continue
		}
		for _, sr := range set.Signatures.Records {
			sm, ok := sr.Message.(*messaging.SignatureMessage)
			if !ok {
				continue
			}
			s, ok := sm.Signature.(*protocol.ED25519Signature)
			if !ok || !s.Signer.Equal(page) {
				continue
			}
			b, err := s.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if !seen[string(b)] {
				seen[string(b)] = true
				out = append(out, b)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	if len(out) == 0 {
		return nil, fmt.Errorf("no ED25519 signature from %v is recorded for %v", page, txid)
	}
	return out, nil
}
