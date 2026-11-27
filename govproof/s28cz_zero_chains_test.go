// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof_test

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
)

// AN ACCOUNT THAT LISTS NO CHAINS IS PROVABLE (infrix-core L3260): Accumulate writes a genesis key page or key book with no chain until it signs,
// and hashChains then hashes an empty list (the zero hash). Such an account's state recomputes to MerkleRoot(main, secondary, zero, pending) and
// hands no chain up (ChainAnchor nil); a chain index naming a chain of an account that lists none is refused; and an account that must hand a chain
// up (the Directory ledger) is refused by name when it lists none, never indexed out of range.
func TestS28czAnAccountThatListsNoChainsIsProvable(t *testing.T) {
	f := loadDirRoot(t)
	a := f.Proof.PageState
	a.Chains, a.StatePath = nil, nil
	st, err := a.State(nil)
	if err != nil {
		t.Fatalf("an account that lists no chains: %v", err)
	}
	main := sha256.Sum256(a.MainState)
	want := l0proof.MerkleRoot([][]byte{main[:], a.SecondaryState, make([]byte, 32), a.Pending})
	if !bytes.Equal(st.Root, want) || st.ChainAnchor != nil {
		t.Fatalf("the account's state root %X (chain anchor %X); want %X and no chain handed up", st.Root, st.ChainAnchor, want)
	}
	a.Chain = 1
	if _, err := a.State(nil); err == nil || !strings.Contains(err.Error(), "lists none") {
		t.Fatalf("a chain index into an account that lists no chains: %v", err)
	}
	// an account that lists chains hands the indexed one up
	if st, err := f.Proof.Directory.Ledger.State(nil); err != nil || !bytes.Equal(st.ChainAnchor, f.Proof.Directory.Ledger.Chains[f.Proof.Directory.Ledger.Chain]) {
		t.Fatalf("the Directory ledger's handed-up chain: %v", err)
	}
	// the Directory ledger must hand its root chain up: listing none is refused by name
	p := cloneKP(t, &f.Proof)
	p.Directory.Ledger.Chains, p.Directory.Ledger.Chain = nil, 0
	mustRefuseKP(t, govproof.VerifyKeyPage(p, l0proof.Options{OverridePin: &f.Pin}), "not the Directory ledger's chain")
}
