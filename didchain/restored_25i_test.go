// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"math/big"
	"strings"
	"testing"
)

// THE CHECKS PART 25i REMOVED, RESTORED AS DEFENSE IN DEPTH (core main's ruling 2026-11-16): each reached by a direct test of its own function.

func TestTheDoublingOfAPointWithYZeroIsThePointAtInfinity(t *testing.T) {
	// no secp256k1 point has y = 0; secpAdd still answers the doubling of one as the point at infinity
	a := secpPoint{x: big.NewInt(5), y: big.NewInt(0)}
	if got := secpAdd(a, a); !got.inf {
		t.Fatalf("the doubling of a point with y = 0: %+v", got)
	}
}

func TestARecoveredKeyThatDoesNotVerifyIsRefused(t *testing.T) {
	saved := verifyRecovered
	defer func() { verifyRecovered = saved }()
	verifyRecovered = func(secpPoint, []byte, []byte) bool { return false }
	signature := mustHex(t, "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c")
	if _, err := RecoverSecp256k1(signature[:64], 1, EIP191PersonalMessageHash([]byte("Some data"))); err == nil || !strings.Contains(err.Error(), "recovers no key that verifies it") {
		t.Fatalf("a recovered key that does not verify: %v", err)
	}
}

func TestTheEnvelopeMembersAreTheListAnEntryIsHeldTo(t *testing.T) {
	names := envelopeMemberNames()
	if len(names) != len(envelopeMembers) || names[0] != "document" || names[len(names)-1] != "statement" {
		t.Fatalf("the envelope member names: %v", names)
	}
	if _, err := DecodeEntry([]byte(`{"document":{},"undefined":1}`)); err == nil || !strings.Contains(err.Error(), `carries the member "undefined"`) {
		t.Fatalf("an envelope member the list does not hold: %v", err)
	}
}
