// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	accprotocol "gitlab.com/accumulatenetwork/accumulate/protocol"

	"github.com/AccumulateNetwork/infrix/pkg/evidence"
	l0pkg "github.com/AccumulateNetwork/infrix/pkg/l0"
)

// L0AnchorConfirmation is the result of an independent live L0 lookup of
// an anchor transaction.
type L0AnchorConfirmation struct {
	// Delivered is true when the anchor transaction is committed on L0.
	Delivered bool
	// EntryMatches is true when the on-chain anchor entry commits to the
	// expected bundle (BundleID + BundleHash).
	EntryMatches bool
	// BlockHeight is the L0 block height the anchor was recorded at, when
	// the confirmer can determine it (0 otherwise).
	BlockHeight uint64
	// Detail carries a human-readable explanation of the outcome.
	Detail string
}

// L0AnchorConfirmer fetches an anchor transaction directly from
// Accumulate L0 (by tx hash) and confirms it commits to the expected
// bundle — the trustless heart of the verifier (no Infrix node involved).
type L0AnchorConfirmer interface {
	ConfirmAnchor(ctx context.Context, txHash, expectBundleID string, expectBundleHash [32]byte, expectBlock uint64) (*L0AnchorConfirmation, error)
}

// NativeL0Confirmer is the production confirmer. It talks directly to an
// Accumulate L0 JSON-RPC endpoint (the one the verifier operator
// supplies), queries the anchor transaction by hash, and decodes the
// WriteData entry as the canonical EvidenceAnchorData.
type NativeL0Confirmer struct {
	client *l0pkg.L0Client
}

// NewNativeL0Confirmer builds a confirmer against an L0 endpoint. The
// endpoint accepts the canonical network shorthands (kermit / testnet /
// mainnet / devnet) via l0.ResolveEndpoint.
func NewNativeL0Confirmer(endpoint string) (*NativeL0Confirmer, error) {
	resolved, err := l0pkg.ResolveEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("verifykit: resolve L0 endpoint: %w", err)
	}
	if strings.TrimSpace(resolved) == "" {
		return nil, fmt.Errorf("verifykit: empty L0 endpoint")
	}
	cfg := l0pkg.DefaultClientConfig()
	cfg.Endpoints = []string{resolved}
	client, err := l0pkg.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("verifykit: build L0 client: %w", err)
	}
	return &NativeL0Confirmer{client: client}, nil
}

// ConfirmAnchor implements L0AnchorConfirmer.
func (c *NativeL0Confirmer) ConfirmAnchor(ctx context.Context, txHash, expectBundleID string, expectBundleHash [32]byte, expectBlock uint64) (*L0AnchorConfirmation, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(txHash), "0x")
	hashBytes, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("verifykit: anchor tx hash %q is not hex: %w", txHash, err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("verifykit: anchor tx hash must be 32 bytes, got %d", len(hashBytes))
	}

	resp, err := c.client.GetTransaction(ctx, hashBytes)
	if err != nil {
		return nil, fmt.Errorf("verifykit: query L0 anchor tx: %w", err)
	}
	conf := &L0AnchorConfirmation{Delivered: resp.Delivered}
	if !resp.Delivered {
		conf.Detail = "transaction present but not yet delivered"
		return conf, nil
	}

	// Extract the WriteData entry and decode it as EvidenceAnchorData.
	entry, derr := extractWriteDataEntry(resp)
	if derr != nil {
		conf.Detail = derr.Error()
		return conf, nil
	}
	var anchorData evidence.EvidenceAnchorData
	if jerr := json.Unmarshal(entry, &anchorData); jerr != nil {
		conf.Detail = "L0 anchor entry is not canonical EvidenceAnchorData: " + jerr.Error()
		return conf, nil
	}
	conf.BlockHeight = anchorData.BlockHeight

	if anchorData.BundleID == expectBundleID && anchorData.BundleHash == expectBundleHash {
		conf.EntryMatches = true
		conf.Detail = "on-chain anchor commits to bundle " + expectBundleID
		return conf, nil
	}
	// Batch anchor: the on-chain payload may be a batch record listing
	// multiple bundle commitments.
	if matchBatchEntry(entry, expectBundleID, expectBundleHash) {
		conf.EntryMatches = true
		conf.Detail = "bundle found in on-chain batch anchor"
		return conf, nil
	}
	conf.Detail = fmt.Sprintf("on-chain anchor entry does not commit to bundle %s (found bundleId=%q)", expectBundleID, anchorData.BundleID)
	return conf, nil
}

// extractWriteDataEntry pulls the first data chunk from a WriteData
// transaction body.
func extractWriteDataEntry(resp *l0pkg.TransactionQueryResponse) ([]byte, error) {
	if resp == nil || resp.Transaction == nil {
		return nil, fmt.Errorf("anchor tx carries no transaction body")
	}
	wd, ok := resp.Transaction.Body.(*accprotocol.WriteData)
	if !ok {
		return nil, fmt.Errorf("anchor tx body is %T, not WriteData", resp.Transaction.Body)
	}
	if wd.Entry == nil {
		return nil, fmt.Errorf("anchor tx WriteData has no entry")
	}
	chunks := wd.Entry.GetData()
	if len(chunks) == 0 {
		return nil, fmt.Errorf("anchor tx WriteData entry is empty")
	}
	if len(chunks) == 1 {
		return chunks[0], nil
	}
	total := 0
	for _, ch := range chunks {
		total += len(ch)
	}
	out := make([]byte, 0, total)
	for _, ch := range chunks {
		out = append(out, ch...)
	}
	return out, nil
}

// matchBatchEntry checks whether a batch anchor record contains the
// expected bundle commitment.
func matchBatchEntry(entry []byte, expectBundleID string, expectBundleHash [32]byte) bool {
	var batch evidence.BatchEvidenceAnchorData
	if err := json.Unmarshal(entry, &batch); err != nil {
		return false
	}
	for _, e := range batch.Entries {
		if e.BundleID == expectBundleID && e.BundleHash == expectBundleHash {
			return true
		}
	}
	return false
}

// compile-time assertion.
var _ L0AnchorConfirmer = (*NativeL0Confirmer)(nil)
