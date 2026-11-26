package l0proof_test

import (
	"testing"
	"time"

	"github.com/opendlt/infrix-verify/l0proof"
)

// lastHeaderTime is the time of the header the Kermit trace certifies (the latest trusted header reached from the pin).
func lastHeaderTime(t *testing.T) (*fixture, time.Time) {
	t.Helper()
	f := loadFixture(t, "kermit")
	h := f.chain.Consensus[len(f.chain.Consensus)-1].Header.Time
	return f, time.Unix(h.Seconds, int64(h.Nanos)).UTC()
}

func withClock(f *fixture, c *l0proof.RelyingPartyClock) l0proof.Options {
	o := f.opts
	o.Clock = c
	return o
}

// 28bg ruling 4: with the relying party's clock, a trace whose latest trusted header is inside CometBFT's trusting period verifies and the
// verdict records the clock and the period; without the clock the same proof verifies and is reported clock-unchecked.
func TestClock_AppliedWhenSuppliedAndReportedUncheckedWhenNot(t *testing.T) {
	f, last := lastHeaderTime(t)
	now := last.Add(time.Hour)
	r := mustVerify(t, f, f.chain, f.exp, withClock(f, &l0proof.RelyingPartyClock{Now: now}))
	if !r.ClockApplied || r.TrustingPeriod != l0proof.DefaultTrustingPeriod || r.MaxClockDrift != l0proof.DefaultMaxClockDrift || !r.ClockNow.Equal(now) {
		t.Fatalf("the verdict does not record the applied clock: %+v", r)
	}
	unchecked := mustVerify(t, f, f.chain, f.exp, f.opts)
	if unchecked.ClockApplied || unchecked.TrustingPeriod != 0 || !unchecked.ClockNow.IsZero() {
		t.Fatalf("a verdict without a clock must be reported clock-unchecked: %+v", unchecked)
	}
}

// An expired trust fails with the clock: the latest trusted header is older than the trusting period, so it is not credited, and nothing
// is. Bite: one hour inside the period it verifies; and a relying party's own shorter period is enforced and reported.
func TestClock_ExpiredTrustFails(t *testing.T) {
	f, last := lastHeaderTime(t)
	mustFail(t, "a header past the 168h trusting period", f.chain, f.exp,
		withClock(f, &l0proof.RelyingPartyClock{Now: last.Add(l0proof.DefaultTrustingPeriod)}), "expired")
	mustVerify(t, f, f.chain, f.exp, withClock(f, &l0proof.RelyingPartyClock{Now: last.Add(l0proof.DefaultTrustingPeriod - time.Hour)}))
	short := &l0proof.RelyingPartyClock{Now: last.Add(2 * time.Hour), TrustingPeriod: time.Hour}
	r := mustFail(t, "a header past the relying party's own 1h period", f.chain, f.exp, withClock(f, short), "1h0m0s trusting period")
	if r.ClockApplied {
		t.Fatalf("a failed verdict still records an applied clock: %+v", r)
	}
	short.Now = last.Add(30 * time.Minute)
	if r := mustVerify(t, f, f.chain, f.exp, withClock(f, short)); r.TrustingPeriod != time.Hour {
		t.Fatalf("the relying party's period is not reported: %+v", r)
	}
}

// A drift beyond the bound fails: a header timed after the relying party's clock plus the drift bound is from the future. Bite: within the
// 10s bound it verifies.
func TestClock_DriftBeyondTheBoundFails(t *testing.T) {
	f, last := lastHeaderTime(t)
	mustFail(t, "a header 11s ahead of the clock", f.chain, f.exp,
		withClock(f, &l0proof.RelyingPartyClock{Now: last.Add(-11 * time.Second)}), "drift bound")
	mustVerify(t, f, f.chain, f.exp, withClock(f, &l0proof.RelyingPartyClock{Now: last.Add(-9 * time.Second)}))
	mustFail(t, "a header 2s ahead of a 1s drift bound", f.chain, f.exp,
		withClock(f, &l0proof.RelyingPartyClock{Now: last.Add(-2 * time.Second), MaxClockDrift: time.Second}), "drift bound")
}

// A clock with no time, or negative bounds, is refused, never treated as no clock.
func TestClock_MalformedClockIsRefused(t *testing.T) {
	f, last := lastHeaderTime(t)
	mustFail(t, "a zero clock", f.chain, f.exp, withClock(f, &l0proof.RelyingPartyClock{}), "no time")
	mustFail(t, "a negative period", f.chain, f.exp, withClock(f, &l0proof.RelyingPartyClock{Now: last, TrustingPeriod: -time.Hour}), "must not be negative")
}
