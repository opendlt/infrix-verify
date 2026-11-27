// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"strings"
	"testing"
	"time"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

func ts(t time.Time) consensus.Timestamp {
	return consensus.Timestamp{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
}

// TestCheckClockBoundsHopsNotTheProofsAge (main's ruling 2026-11-26, brief 28bs row 6 (d)) over a verified trace's times and validator sets:
//   - one step signed by the pin's own set, years after the pin: trusted directly;
//   - one step signed by a CHANGED set, reached past the trusting period: refused, naming the pin and the need for a newer pin;
//   - a multi-step trace whose second hop spans more than the period: refused;
//   - a multi-step trace within the period: hop-bounded, with its hop count and longest span;
//   - a header timed after the clock plus the drift bound: refused.
func TestCheckClockBoundsHopsNotTheProofsAge(t *testing.T) {
	pinTime := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	pin := &consensus.Pin{Network: "kermit", ChainID: "c", InitialHeight: 1, GenesisTime: ts(pinTime),
		Validators: consensus.ValidatorSet{Validators: []consensus.Validator{{PubKey: make([]byte, 32), VotingPower: 10}}}}
	pinSet := pin.Validators.Hash()
	changed := consensus.ValidatorSet{Validators: []consensus.Validator{{PubKey: append(make([]byte, 31), 1), VotingPower: 10}}}
	block := func(h int64, at time.Time, set []byte) consensus.LightBlock {
		return consensus.LightBlock{Header: consensus.Header{Height: h, Time: ts(at), ValidatorsHash: set}}
	}
	day := 24 * time.Hour
	at := pinTime.Add(298 * day)
	clock := &RelyingPartyClock{Now: at.Add(3 * 365 * day)}

	v, err := checkClock(clock, pin, []consensus.LightBlock{block(13818126, at, pinSet)})
	if err != nil || v.Case != TrustedDirectly || v.MaxHopSpan != 298*day || v.Hops != 1 {
		t.Fatalf("an unchanged set 298 days after the pin is trusted directly: %v %+v", err, v)
	}
	if _, err := checkClock(clock, pin, []consensus.LightBlock{block(13818126, at, changed.Hash())}); err == nil ||
		!strings.Contains(err.Error(), "needs a newer pin") || !strings.Contains(err.Error(), pin.ID()) {
		t.Fatalf("a changed set past the trusting period must be refused naming the pin: %v", err)
	}
	near := pinTime.Add(day)
	if _, err := checkClock(clock, pin, []consensus.LightBlock{block(10, near, pinSet), block(20, near.Add(8*day), pinSet)}); err == nil ||
		!strings.Contains(err.Error(), "hop 2") {
		t.Fatalf("a multi-step hop over the trusting period must be refused: %v", err)
	}
	v, err = checkClock(clock, pin, []consensus.LightBlock{block(10, near, changed.Hash()), block(20, near.Add(6*day), changed.Hash())})
	if err != nil || v.Case != HopBounded || v.Hops != 2 || v.MaxHopSpan != 6*day || !strings.Contains(v.Detail, "hop-bounded: 2 hops") {
		t.Fatalf("hops within the period are hop-bounded: %v %+v", err, v)
	}
	if _, err := checkClock(&RelyingPartyClock{Now: at.Add(-time.Minute)}, pin, []consensus.LightBlock{block(13818126, at, pinSet)}); err == nil ||
		!strings.Contains(err.Error(), "drift bound") {
		t.Fatalf("a header from the future must be refused: %v", err)
	}
}
