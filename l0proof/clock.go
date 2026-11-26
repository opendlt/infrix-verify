// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
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

// checkClock enforces the clock over a verified trace whose last block is last.
func checkClock(c *RelyingPartyClock, trace []consensus.LightBlock, last *consensus.LightBlock) (time.Duration, time.Duration, error) {
	tp, drift, err := c.periods()
	if err != nil {
		return 0, 0, err
	}
	limit := c.Now.Add(drift)
	for _, b := range trace {
		if ht := timeOf(b.Header.Time); ht.After(limit) {
			return tp, drift, fmt.Errorf("the header at height %d is timed %s, after the relying party's clock %s plus the %s drift bound", b.Header.Height, ht.Format(time.RFC3339Nano), c.Now.UTC().Format(time.RFC3339Nano), drift)
		}
	}
	expires := timeOf(last.Header.Time).Add(tp)
	if !expires.After(c.Now) {
		return tp, drift, fmt.Errorf("the latest trusted header (height %d, %s) expired at %s under the %s trusting period; the relying party's clock reads %s", last.Header.Height, timeOf(last.Header.Time).Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), tp, c.Now.UTC().Format(time.RFC3339Nano))
	}
	return tp, drift, nil
}
