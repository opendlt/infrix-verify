// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"bytes"
	"fmt"
	"time"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// CometBFT's light-client defaults (cmd/cometbft/commands/light.go trustingPeriod "168h"; light/verifier.go and light/client.go
// defaultMaxClockDrift = 10 * time.Second), used when a RelyingPartyClock leaves them zero.
const (
	DefaultTrustingPeriod = 168 * time.Hour
	DefaultMaxClockDrift  = 10 * time.Second
)

// RelyingPartyClock is the relying party's own clock (28bg ruling 4, brief 28bi). The verifier has no clock of its own and never takes a
// time from the proof. When the relying party supplies one, CometBFT's two time checks are ENFORCED:
//
//   - the trusting period (light/verifier.go HeaderExpired): the latest header the trace reaches from the pin, the one whose AppHash the
//     chain is proven to, must not have expired: Now must be before its time plus TrustingPeriod. A header older than that may have been
//     signed by validators who have since unbonded (the long-range window), so it is not credited;
//   - the clock drift (light/verifier.go verifyNewHeaderAndVals, "new header has a time from the future"): no header in the trace may be
//     timed after Now plus MaxClockDrift.
//
// Without a clock neither check is made, and the Result says so (ClockApplied false): the compensating rule is the stricter 2/3 trust level.
type RelyingPartyClock struct {
	Now            time.Time
	TrustingPeriod time.Duration // zero means DefaultTrustingPeriod
	MaxClockDrift  time.Duration // zero means DefaultMaxClockDrift
}

func (c *RelyingPartyClock) periods() (time.Duration, time.Duration, error) {
	tp, drift := c.TrustingPeriod, c.MaxClockDrift
	if tp == 0 {
		tp = DefaultTrustingPeriod
	}
	if drift == 0 {
		drift = DefaultMaxClockDrift
	}
	if tp < 0 || drift < 0 {
		return 0, 0, fmt.Errorf("the relying-party clock's trusting period %s and drift %s must not be negative", tp, drift)
	}
	if c.Now.IsZero() {
		return 0, 0, fmt.Errorf("the relying-party clock has no time")
	}
	return tp, drift, nil
}

func timeOf(t consensus.Timestamp) time.Time { return time.Unix(t.Seconds, int64(t.Nanos)).UTC() }

// Trust cases a clocked verdict reports (ClockVerdict.Case).
const (
	// TrustedDirectly: every header the trace reaches carries the pin's own validator set, which the relying party trusts directly, so no
	// light-client hop crosses a validator change and the trusting period bounds nothing (main's ruling 2026-11-26, brief 28bs row 6 (d)).
	TrustedDirectly = "trusted-directly"
	// HopBounded: the trace crosses a validator change or has more than one step, and every hop is held to the trusting period.
	HopBounded = "hop-bounded"
)

// ClockVerdict is how the relying party's clock was applied to a verified trace.
type ClockVerdict struct {
	TrustingPeriod time.Duration
	MaxClockDrift  time.Duration
	Case           string        // TrustedDirectly or HopBounded
	MeasuredFrom   time.Time     // the pin's time: the trusted state the first hop starts from
	Hops           int           // the trace's steps
	MaxHopSpan     time.Duration // the longest span between a hop's trusted time and the header it reaches
	Detail         string        // the case in words, with the pin time, the header time and the spans
}

// checkClock enforces the relying party's clock over a verified trace from pin (main's ruling 2026-11-26, brief 28bs row 6 (d)):
//
//   - the DRIFT check, always against the relying party's clock: no header may be timed after Now plus MaxClockDrift;
//   - the TRUSTING PERIOD bounds light-client HOPS, never the age of the proof against the wall clock: the relying party trusts the pin's
//     validator set directly, so a single step reaching a header still signed by exactly that set crosses no validator change and is
//     trusted directly, however long after the pin it is timed (a bundle stays verifiable offline forever under its pin). Every other hop
//     (a step whose validator set differs from the pin's, and every step after the first) must reach its header within TrustingPeriod of
//     the trusted time it starts from; a validator change past the period is refused by name: the relying party needs a newer pin.
func checkClock(c *RelyingPartyClock, pin *consensus.Pin, trace []consensus.LightBlock) (*ClockVerdict, error) {
	tp, drift, err := c.periods()
	if err != nil {
		return nil, err
	}
	limit := c.Now.Add(drift)
	for _, b := range trace {
		if ht := timeOf(b.Header.Time); ht.After(limit) {
			return nil, fmt.Errorf("the header at height %d is timed %s, after the relying party's clock %s plus the %s drift bound", b.Header.Height, ht.Format(time.RFC3339Nano), c.Now.UTC().Format(time.RFC3339Nano), drift)
		}
	}
	v := &ClockVerdict{TrustingPeriod: tp, MaxClockDrift: drift, MeasuredFrom: timeOf(pin.GenesisTime), Hops: len(trace)}
	pinSet := pin.Validators.Hash()
	if len(trace) == 1 && bytes.Equal(trace[0].Header.ValidatorsHash, pinSet) {
		ht := timeOf(trace[0].Header.Time)
		v.Case, v.MaxHopSpan = TrustedDirectly, ht.Sub(v.MeasuredFrom)
		v.Detail = fmt.Sprintf("trusted directly: validator set unchanged since the pin (pin time %s, header time %s)", v.MeasuredFrom.Format(time.RFC3339), ht.Format(time.RFC3339))
		return v, nil
	}
	v.Case = HopBounded
	from := v.MeasuredFrom
	for i, b := range trace {
		ht := timeOf(b.Header.Time)
		span := ht.Sub(from)
		if span > v.MaxHopSpan {
			v.MaxHopSpan = span
		}
		if span > tp {
			if !bytes.Equal(b.Header.ValidatorsHash, pinSet) {
				return nil, fmt.Errorf("the header at height %d (%s) is signed by a validator set changed since pin %s and is reached %s after the trusted time %s, over the %s trusting period: the relying party needs a newer pin", b.Header.Height, ht.Format(time.RFC3339), pin.ID(), span, from.Format(time.RFC3339), tp)
			}
			return nil, fmt.Errorf("hop %d reaches the header at height %d (%s) %s after the trusted time %s, over the %s trusting period", i+1, b.Header.Height, ht.Format(time.RFC3339), span, from.Format(time.RFC3339), tp)
		}
		from = ht
	}
	v.Detail = fmt.Sprintf("hop-bounded: %d hops, max span %s within the %s trusting period from the pin (pin time %s)", len(trace), v.MaxHopSpan, tp, v.MeasuredFrom.Format(time.RFC3339))
	return v, nil
}
