package l0proof_test

import (
	"strings"
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

// Main's ruling 2026-11-26 (brief 28bs row 6 (d)): the trusting period bounds light-client hops, never the proof's age against the wall
// clock. The Kermit trace is one step whose header (about 298 days after the compiled pin's time) is still signed by the pin's own validator
// set, which the relying party trusts directly: with the clock three years ahead it still verifies, reported as trusted directly with the pin
// time and the header time; and a relying party's own short period does not expire it either. (The refusals, a changed validator set over
// the period and a multi-step hop over it, are TestCheckClockBoundsHopsNotTheProofsAge.)
func TestClock_ATraceTrustedDirectlyByThePinNeverExpires(t *testing.T) {
	f, last := lastHeaderTime(t)
	for _, c := range []*l0proof.RelyingPartyClock{
		{Now: last.Add(3 * 365 * 24 * time.Hour)},
		{Now: last.Add(2 * time.Hour), TrustingPeriod: time.Hour},
	} {
		r := mustVerify(t, f, f.chain, f.exp, withClock(f, c))
		if !r.ClockApplied || r.Clock == nil || r.Clock.Case != l0proof.TrustedDirectly || !strings.Contains(r.Clock.Detail, "trusted directly: validator set unchanged since the pin") ||
			r.Clock.MaxHopSpan != last.Sub(r.Clock.MeasuredFrom) {
			t.Fatalf("a header signed by the pin's own set is trusted directly whatever its age: %+v", r.Clock)
		}
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
