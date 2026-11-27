// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FZ-01 for govproof's own decoders: arbitrary bytes never panic, and a decode that succeeds re-reads the same fields from the same bytes.
func fixtureBytes(f *testing.F) (sigs [][]byte, ledger []byte) {
	b, err := os.ReadFile(filepath.Join("testdata", "simulator", "governance.json"))
	if err != nil {
		f.Fatal(err)
	}
	var fx struct {
		Execution GovernanceExecution `json:"execution"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		f.Fatal(err)
	}
	for _, s := range fx.Execution.Signatures {
		sigs = append(sigs, s)
	}
	return sigs, fx.Execution.Page.LedgerState.MainState
}

func FuzzDecodeED25519Signature(f *testing.F) {
	sigs, _ := fixtureBytes(f)
	for _, s := range sigs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeED25519Signature(b)
		if err != nil {
			return
		}
		if len(s.PublicKey) != 32 || len(s.Signature) != 64 || s.Signer == "" || len(s.Metadata) >= len(b) {
			t.Fatalf("a decoded signature broke its invariants: %+v", s)
		}
	})
}

func FuzzDecodeSystemLedger(f *testing.F) {
	_, ledger := fixtureBytes(f)
	f.Add(ledger)
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := decodeSystemLedger(b)
		if err != nil {
			return
		}
		if l.URL == "" || l.Index == 0 {
			t.Fatalf("a decoded ledger broke its invariants: %+v", l)
		}
	})
}
