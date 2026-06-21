// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import "context"

// This file defines the verifier's L0 PORT: the L0AnchorConfirmer interface and
// its result type. The runtime ADAPTER that talks to a live Accumulate L0
// endpoint (NativeL0Confirmer, which imports pkg/l0) lives in the sibling
// package pkg/verifykit/l0native (docs/extraction-plan, M4.2). Keeping only the
// port here is what lets the verifier core compile with NO dependency on the
// live L0 client — confirmation is injected by the application, never compiled
// in, so a third party can verify with zero trust in the node.

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
// The production implementation is l0native.NativeL0Confirmer.
type L0AnchorConfirmer interface {
	ConfirmAnchor(ctx context.Context, txHash, expectBundleID string, expectBundleHash [32]byte, expectBlock uint64) (*L0AnchorConfirmation, error)
}
