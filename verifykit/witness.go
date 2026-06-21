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

	"github.com/AccumulateNetwork/infrix-schema/evidence"
	"github.com/AccumulateNetwork/infrix/pkg/witness"
)

// witnessGate carries the witness-evaluation policy from Options.
type witnessGate struct {
	authorizer        witness.KeyPageAuthorizer
	nowUnix           int64
	maxAgeSeconds     int64
	requireThreshold  int
	operators         map[string]string // witness identity -> independent operator ID
	requireRegistered bool
	requireOperators  int // minimum DISTINCT independent operators
}

// evaluateWitnesses validates any witness receipts carried in the package
// against the bundle facts, deduplicates by witness identity, judges
// INDEPENDENCE by distinct operators (not just distinct keys), and sets the
// witness report fields. Failed checks are added (fail-closed) when the
// distinct-witness or distinct-operator threshold is not met.
func (r *Report) evaluateWitnesses(pkg *evidence.PortableEvidencePackage, bundle *evidence.EvidenceBundle, anchored bool, g witnessGate) {
	receipts := decodeReceipts(pkg)

	exp := witness.Expected{
		OutcomeHash:                hex.EncodeToString(pkg.OutcomeDigest[:]),
		ReplayCapsuleHash:          capsuleHash(pkg),
		NowUnix:                    g.nowUnix,
		MaxAgeSeconds:              g.maxAgeSeconds,
		WitnessOperators:           g.operators,
		RequireRegisteredWitnesses: g.requireRegistered,
	}
	if anchored {
		exp.L0AnchorTxHash = bundle.AnchorTxHash
	}

	ev := witness.EvaluateAuthorized(receipts, exp, g.authorizer)
	r.WitnessCount = ev.ValidCount
	r.WitnessVerified = ev.ValidCount > 0
	r.IndependentReplayVerified = ev.ValidCount > 0
	r.WitnessThresholdMet = ev.ThresholdMet(g.requireThreshold)
	r.WitnessOperatorCount = ev.DistinctOperators
	r.WitnessOperatorThresholdMet = ev.OperatorThresholdMet(g.requireOperators)

	switch {
	case len(receipts) == 0 && g.requireThreshold == 0 && g.requireOperators == 0:
		// No receipts and none required — nothing to report.
		return
	case len(receipts) == 0:
		r.add("witness_threshold", CheckFail, fmt.Sprintf("require %d witness(es) / %d operator(s), bundle carries none", g.requireThreshold, g.requireOperators))
		return
	}

	detail := fmt.Sprintf("%d distinct valid witness(es) across %d independent operator(s)", ev.ValidCount, ev.DistinctOperators)
	if len(ev.DuplicateIdentities) > 0 {
		detail += fmt.Sprintf("; %d duplicate identity(ies) rejected", len(ev.DuplicateIdentities))
	}
	if len(ev.Rejected) > 0 {
		detail += fmt.Sprintf("; %d receipt(s) rejected", len(ev.Rejected))
	}
	r.add("witness", CheckPass, detail)

	if g.requireThreshold > 0 && !r.WitnessThresholdMet {
		r.add("witness_threshold", CheckFail, fmt.Sprintf("require %d witness(es), got %d valid", g.requireThreshold, ev.ValidCount))
	}
	if g.requireOperators > 0 && !r.WitnessOperatorThresholdMet {
		r.add("witness_operator_diversity", CheckFail, fmt.Sprintf("require %d DISTINCT independent operator(s), got %d (witnesses must run from distinct operators, not one operator's keys)", g.requireOperators, ev.DistinctOperators))
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
