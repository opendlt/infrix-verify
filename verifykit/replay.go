// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"

	"github.com/AccumulateNetwork/infrix-schema/evidence"
)

// ReplayMaterial is the set of inputs deterministic replay needs to
// re-execute the recorded outcome. Replay is STRICTER than verify: it
// re-runs the contract against the recorded inputs and checks the
// re-derived outcome digest matches the bundle's.
type ReplayMaterial struct {
	// ContractBytecode is the WASM/EVM bytecode that executed.
	ContractBytecode []byte
	// PluginInventory pins the plugin implementation hashes.
	PluginInventory []evidence.PluginVersionEntry
	// StateSnapshot is the pre-execution state the replay forks from.
	StateSnapshot []byte
	// DeterministicInputs are the recorded runtime inputs (block time,
	// caller, args) that make the re-execution deterministic.
	DeterministicInputs map[string][]byte
}

// Complete reports whether every replay input is present. Replay refuses
// to run on partial material — a half-replay would produce a misleading
// verdict.
//
// platform-review-3 Epic 2: contract bytecode is no longer a hard
// requirement, because not every governed operation is a contract
// execution (escrow/approval flows have no bytecode). Replay requires the
// plugin inventory, a pre-execution state snapshot, and the deterministic
// inputs — the material common to every replayable operation. A contract
// flow still carries bytecode; its absence simply no longer blocks
// replay of a non-contract flow.
func (m *ReplayMaterial) Complete() bool {
	if m == nil {
		return false
	}
	return len(m.PluginInventory) > 0 &&
		len(m.StateSnapshot) > 0 &&
		len(m.DeterministicInputs) > 0
}

// ReplayProvider supplies replay material for a bundle and re-executes
// it deterministically, returning the re-derived outcome digest. The
// interface is the seam an operator-supplied replay engine (or a test)
// implements; the kit itself only orchestrates and compares.
type ReplayProvider interface {
	// Material returns the replay material available for this bundle (or
	// an incomplete struct when material is missing).
	Material(ctx context.Context, bundle *evidence.EvidenceBundle) (*ReplayMaterial, error)
	// Replay re-executes the bundle from material and returns the
	// re-derived outcome digest.
	Replay(ctx context.Context, bundle *evidence.EvidenceBundle, material *ReplayMaterial) (outcomeDigest [32]byte, err error)
}

// runReplay drives the optional deterministic-replay step. Per the spec
// it is stricter than verify and, when material is unavailable, reports
// availability=false WITHOUT downgrading the cryptographic/L0 verdict.
func runReplay(ctx context.Context, pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, provider ReplayProvider) *ReplayResult {
	if provider == nil {
		return &ReplayResult{
			Available: false,
			Detail:    "cryptographic verification passed, deterministic replay unavailable (no replay provider supplied)",
		}
	}
	material, err := provider.Material(ctx, bundle)
	if err != nil {
		return &ReplayResult{
			Available: false,
			Detail:    "cryptographic verification passed, deterministic replay unavailable: " + err.Error(),
		}
	}
	if !material.Complete() {
		return &ReplayResult{
			Available: false,
			Detail:    "cryptographic verification passed, deterministic replay unavailable (replay material incomplete: needs contract bytecode, plugin inventory, state snapshot, and deterministic inputs)",
		}
	}
	rederived, err := provider.Replay(ctx, bundle, material)
	if err != nil {
		return &ReplayResult{
			Available: true,
			Matched:   false,
			Detail:    "deterministic replay failed: " + err.Error(),
		}
	}
	if rederived != pkg.OutcomeDigest {
		return &ReplayResult{
			Available: true,
			Matched:   false,
			Detail:    "deterministic replay produced a DIFFERENT outcome digest than the bundle — execution does not reproduce",
		}
	}
	return &ReplayResult{
		Available: true,
		Matched:   true,
		Detail:    "deterministic replay reproduced the recorded outcome digest",
	}
}
