// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-schema/policyeval"
)

// THE PAGES A BUNDLE PROVES ANSWER ACTOR::HAS_KEY THROUGH THE NODE'S OWN BODY (infrix-core L3196, main's ruling 2026-11-27): actor::has_key(page
// [, identity]) is the page exists AND the subject holds an entry on it. A page proven under the pin, as an approval page or an operand page,
// answers from its proven entries: the lite identity of a key it lists holds it (1), an identity with no entry on it does not (a proven 0); a
// page nothing proves stays unproven (ErrAbsenceNotProvable); a page proof that does not verify fails the check.
func TestS28ctTheProvenPagesAnswerActorHasKeyThroughTheNodesBody(t *testing.T) {
	o := accOpts(t)
	p := loadAccProofs(t)
	b := &evidence.EvidenceBundle{OperandPageProofs: p.KeyPageProofs}
	pages, err := verifiedKeyPages(b, o)
	if err != nil {
		t.Fatalf("the committed page proofs as operand pages: %v", err)
	}
	entries, ok := pages[strings.ToLower(accPage)]
	if !ok || len(entries.KeyHashes) == 0 {
		t.Fatalf("the proven pages %v miss %s or its keys", pages, accPage)
	}
	holder := "acc://" + s28cuLiteIdentity(entries.KeyHashes[0][:20])
	c := &policyeval.ProvenRolesContext{Subject: policyeval.Subject{Actor: holder}, ProvenPages: pages}
	if v, err := c.ResolveOperand(policyeval.OpActorHasKey, []string{accPage}); err != nil || v != policyeval.TruthOperand(true) {
		t.Fatalf("actor::has_key(%s) for the lite identity of its key = %v, %v; want 1", accPage, v, err)
	}
	if v, err := c.ResolveOperand(policyeval.OpActorHasKey, []string{accPage, "acc://s28cu-nobody.acme"}); err != nil || v != policyeval.TruthOperand(false) {
		t.Fatalf("actor::has_key(%s) for an identity with no entry = %v, %v; want a proven 0", accPage, v, err)
	}
	if v, err := c.ResolveOperand(policyeval.OpActorHasKey, []string{accPage + "-unproven"}); !errors.Is(err, policyeval.ErrAbsenceNotProvable) {
		t.Fatalf("actor::has_key of an unproven page answered %v, %v; want ErrAbsenceNotProvable", v, err)
	}
	// a tampered page proof fails, whichever list carries it
	bad := append([]byte(nil), p.KeyPageProofs[0]...)
	i := strings.Index(string(bad), `"height":`)
	if i < 0 {
		t.Fatal("premise: the page proof names its height")
	}
	bad[i+len(`"height":`)]++
	if _, err := verifiedKeyPages(&evidence.EvidenceBundle{OperandPageProofs: []json.RawMessage{bad}}, o); err == nil {
		t.Fatal("a tampered operand page proof verified")
	}
}

// s28cuLiteIdentity is Accumulate's lite identity authority for a key hash prefix (hex of the 20 bytes, then the hex of the last 4 bytes of the
// SHA-256 of that hex).
func s28cuLiteIdentity(prefix []byte) string {
	h := hex.EncodeToString(prefix)
	sum := sha256.Sum256([]byte(h))
	return h + hex.EncodeToString(sum[28:])
}
