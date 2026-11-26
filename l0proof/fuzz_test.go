// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

func canonicalJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("null"), []byte("[]"))
}

// FZ-01 for the chain decoder and verifier: no input panics, and nothing is ever credited above what the input proves. A fuzzed encoding that verifies
// under a fixture's expectation and pin must be that fixture's chain (the same statement, at most re-encoded); anything else is a forged credit.
func FuzzDecodeAndVerifyChain(f *testing.F) {
	fx := fixtures(f)
	for _, x := range fx {
		f.Add(x.raw)
		f.Add(x.raw[:len(x.raw)/2])
	}
	f.Add([]byte(`{"incarnation":"x","consensus":[{}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := l0proof.Decode(data, nil)
		if err != nil {
			return
		}
		for _, x := range fx {
			if r := l0proof.Verify(c, x.exp, x.opts); r.Verified {
				if !bytes.Equal(canonicalJSON(t, c), canonicalJSON(t, x.chain)) {
					t.Fatalf("a chain other than the %s fixture verified under its expectation", x.name)
				}
			}
		}
	})
}

// FZ-01 for the consensus decoder: a fuzzed light block that verifies from the simulator pin must be one of the simulator trace's own steps at index 0
// (the only one the pin can certify directly).
func FuzzDecodeAndVerifyLightBlock(f *testing.F) {
	s := loadFixture(f, "simulator")
	first, _ := json.Marshal(s.chain.Consensus[0])
	f.Add(first)
	f.Add([]byte(`{"header":{"height":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var lb consensus.LightBlock
		if json.Unmarshal(data, &lb) != nil {
			return
		}
		if _, err := consensus.VerifyTrace(s.opts.OverridePin, []consensus.LightBlock{lb}, consensus.DefaultLimits); err == nil {
			if !bytes.Equal(canonicalJSON(t, lb), canonicalJSON(t, s.chain.Consensus[0])) {
				t.Fatal("a light block other than the certified one verified from the pin")
			}
		}
	})
}
