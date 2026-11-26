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

// Brief 28bs row 6 (d), main's ruling L3008 (d): the relying party's clock is wired. With a clock inside the trusting period the embedded
// proofs verify (L4/G2) and the report says the clock was applied, with its time and bounds; with a clock past the trusting period the
// anchor chain is refused (below L4); with no clock the verdict stands and the report says it is clock-unchecked.
func TestS28bsTheRelyingPartyClockIsAppliedAndReported(t *testing.T) {
	at := lastHeaderTime(t)
	o := accOpts(t)
	o.Clock = &l0proof.RelyingPartyClock{Now: at.Add(time.Hour)}
	r := Verify(context.Background(), accPackage(t, nil), o)
	if !r.Verified || r.ProofLevel != "L4" || r.GovernanceLevel != "G2" {
		t.Fatalf("inside the trusting period: %s/%s verified=%v %s", r.ProofLevel, r.GovernanceLevel, r.Verified, detail(r, "embedded_l0_proof"))
	}
	if c := r.Clock; c == nil || !c.Applied || c.Now != at.Add(time.Hour).Format(time.RFC3339) || c.TrustingPeriod != l0proof.DefaultTrustingPeriod.String() ||
		c.MaxClockDrift != l0proof.DefaultMaxClockDrift.String() {
		t.Fatalf("the clock is not reported as applied with its time and bounds: %+v", r.Clock)
	}

	o.Clock = &l0proof.RelyingPartyClock{Now: at.Add(l0proof.DefaultTrustingPeriod + time.Hour)}
	if r := Verify(context.Background(), accPackage(t, nil), o); r.ProofLevel == "L4" || checkStatus(r, "embedded_l0_proof") != CheckFail {
		t.Fatalf("past the trusting period the anchor chain must be refused: %s %s", r.ProofLevel, detail(r, "embedded_l0_proof"))
	}

	o.Clock = nil
	r = Verify(context.Background(), accPackage(t, nil), o)
	if r.ProofLevel != "L4" || r.Clock == nil || r.Clock.Applied {
		t.Fatalf("with no clock the verdict stands and is reported clock-unchecked: %s %+v", r.ProofLevel, r.Clock)
	}
}
