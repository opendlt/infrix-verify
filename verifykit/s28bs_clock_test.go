// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/opendlt/infrix-verify/l0proof"
)

// lastHeaderTime is the time of the last Directory header the fixture's anchor chain certifies.
func lastHeaderTime(t *testing.T) time.Time {
	t.Helper()
	var c l0proof.L0ProofChain
	if err := json.Unmarshal(loadAccProofs(t).L0Proof, &c); err != nil {
		t.Fatal(err)
	}
	last := c.Consensus[len(c.Consensus)-1].Header.Time
	return time.Unix(last.Seconds, int64(last.Nanos)).UTC()
}

// Brief 28bs row 6 (d), main's ruling L3008 (d) and 2026-11-26: the relying party's clock is wired. The fixture's trace is two steps (hop-bounded,
// each hop within the trusting period of the one before), so its age never expires it: with the clock an hour or three years after the header the embedded proofs verify (L4/G2)
// and the report says the clock was applied, the drift checked, and which trust case held; a header from the future (the clock a minute
// before it) is refused (below L4); with no clock the verdict stands and the report says it is clock-unchecked.
func TestS28bsTheRelyingPartyClockIsAppliedAndReported(t *testing.T) {
	at := lastHeaderTime(t)
	o := accOpts(t)
	o.Clock = &l0proof.RelyingPartyClock{Now: at.Add(time.Hour)}
	r := Verify(context.Background(), accPackage(t, nil), o)
	if !r.Verified || r.ProofLevel != "L4" || r.GovernanceLevel != "G2" {
		t.Fatalf("inside the trusting period: %s/%s verified=%v %s", r.ProofLevel, r.GovernanceLevel, r.Verified, detail(r, "embedded_l0_proof"))
	}
	if c := r.Clock; c == nil || !c.Applied || !c.DriftChecked || c.Now != at.Add(time.Hour).Format(time.RFC3339) || c.TrustingPeriod != l0proof.DefaultTrustingPeriod.String() ||
		c.MaxClockDrift != l0proof.DefaultMaxClockDrift.String() || c.Case != l0proof.HopBounded || c.MeasuredFrom == "" || c.Detail == "" {
		t.Fatalf("the clock is not reported as applied with its time, bounds and trust case: %+v", r.Clock)
	}

	o.Clock = &l0proof.RelyingPartyClock{Now: at.Add(3 * 365 * 24 * time.Hour)}
	if r := Verify(context.Background(), accPackage(t, nil), o); !r.Verified || r.ProofLevel != "L4" || r.GovernanceLevel != "G2" {
		t.Fatalf("years later the bundle stays L4/G2 offline under its pin: %s/%s %s", r.ProofLevel, r.GovernanceLevel, detail(r, "embedded_l0_proof"))
	}

	o.Clock = &l0proof.RelyingPartyClock{Now: at.Add(-time.Minute)}
	if r := Verify(context.Background(), accPackage(t, nil), o); r.ProofLevel == "L4" || checkStatus(r, "embedded_l0_proof") != CheckFail {
		t.Fatalf("a header from the future must be refused: %s %s", r.ProofLevel, detail(r, "embedded_l0_proof"))
	}

	o.Clock = nil
	r = Verify(context.Background(), accPackage(t, nil), o)
	if r.ProofLevel != "L4" || r.Clock == nil || r.Clock.Applied {
		t.Fatalf("with no clock the verdict stands and is reported clock-unchecked: %s %+v", r.ProofLevel, r.Clock)
	}
}
