// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import "context"

// This file defines the verifier's EXTERNAL-PROOF PORT, mirroring the
// L0AnchorConfirmer port. An EvidenceBundle may reference a proof from an
// external chain/system (evidence.ExternalProofRef). That reference carries a
// self-asserted `Verified` flag set by the PRODUCING node — which the verifier
// must not trust (that is exactly the "no node trust" property, DX P0-5b). So
// governance level G2 (credentialed + anchored) is credited ONLY when an
// application-injected ExternalProofConfirmer independently re-reads the external
// proof from its source and confirms it (DX P1-4). With no confirmer, governance
// caps at G1 — the honest default.
//
// Like L0AnchorConfirmer, only the PORT lives in the verifier core; the concrete
// ADAPTER (which talks to the external chain) is injected by the application, so
// the core keeps zero dependency on any live client.

// ExternalProofConfirmation is the result of an independent lookup of an
// external-chain proof referenced by an evidence bundle.
type ExternalProofConfirmation struct {
	// Confirmed is true when the external proof exists at the referenced
	// coordinates and commits to the expected proof hash.
	Confirmed bool
	// Detail carries a human-readable explanation of the outcome.
	Detail string
}

// ExternalProofConfirmer independently confirms an evidence bundle's external
// proof reference against its source chain — the honest replacement for trusting
// evidence.ExternalProofRef.Verified.
type ExternalProofConfirmer interface {
	ConfirmExternalProof(ctx context.Context, sourceChain, proofType, txHash string, proofHash [32]byte, blockHeight uint64) (*ExternalProofConfirmation, error)
}
