// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/AccumulateNetwork/infrix/pkg/evidence"
	"github.com/AccumulateNetwork/infrix/pkg/witness"
)

// evaluateWitnesses validates any witness receipts carried in the package
// against the bundle facts, deduplicates by witness identity, and sets the
// witness report fields. When requireThreshold > 0 and the distinct valid
// witness count does not meet it, a failed check is added so verification
// fails closed. platform-review-3 Epic 5.
func (r *Report) evaluateWitnesses(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, anchored bool, requireThreshold int) {
	receipts := decodeReceipts(pkg)

	exp := witness.Expected{
		OutcomeHash:       hex.EncodeToString(pkg.OutcomeDigest[:]),
		ReplayCapsuleHash: capsuleHash(pkg),
	}
	if anchored {
		exp.L0AnchorTxHash = bundle.AnchorTxHash
	}

	ev := witness.Evaluate(receipts, exp)
	r.WitnessCount = ev.ValidCount
	r.WitnessVerified = ev.ValidCount > 0
	r.IndependentReplayVerified = ev.ValidCount > 0
	r.WitnessThresholdMet = ev.ThresholdMet(requireThreshold)

	switch {
	case len(receipts) == 0 && requireThreshold == 0:
		// No receipts and none required — nothing to report.
		return
	case len(receipts) == 0:
		r.add("witness_threshold", CheckFail, fmt.Sprintf("require %d witness(es), bundle carries none", requireThreshold))
		return
	}

	detail := fmt.Sprintf("%d distinct valid witness(es)", ev.ValidCount)
	if len(ev.DuplicateIdentities) > 0 {
		detail += fmt.Sprintf("; %d duplicate identity(ies) rejected", len(ev.DuplicateIdentities))
	}
	if len(ev.Rejected) > 0 {
		detail += fmt.Sprintf("; %d receipt(s) rejected", len(ev.Rejected))
	}
	r.add("witness", CheckPass, detail)

	if requireThreshold > 0 && !r.WitnessThresholdMet {
		r.add("witness_threshold", CheckFail, fmt.Sprintf("require %d witness(es), got %d valid", requireThreshold, ev.ValidCount))
	}
}

// decodeReceipts decodes the package's raw witness receipts, skipping any
// that do not parse (a malformed receipt is simply not counted).
func decodeReceipts(pkg *evidence.PortableEvidencePackage) []witness.Receipt {
	out := make([]witness.Receipt, 0, len(pkg.WitnessReceipts))
	for _, raw := range pkg.WitnessReceipts {
		var rc witness.Receipt
		if err := json.Unmarshal(raw, &rc); err != nil {
			continue
		}
		out = append(out, rc)
	}
	return out
}

// capsuleHash is the sha256-hex of the package's replay capsule bytes, or
// "" when no capsule is present.
func capsuleHash(pkg *evidence.PortableEvidencePackage) string {
	if !pkg.HasReplayCapsule() {
		return ""
	}
	return witness.HashBytes(pkg.ReplayCapsule)
}
