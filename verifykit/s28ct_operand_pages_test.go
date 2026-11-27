// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-schema/policyeval"
)

// THE PAGES A BUNDLE PROVES ANSWER ACTOR::HAS_KEY THROUGH THE NODE'S OWN BODY (infrix-core L3196): a page proven under the pin, as an approval page
// or an operand page, re-decides actor::has_key to 1; a page proof that does not verify fails the check; a page nothing proves stays unproven.
func TestS28ctTheProvenPagesAnswerActorHasKeyThroughTheNodesBody(t *testing.T) {
	o := accOpts(t)
	p := loadAccProofs(t)
	b := &evidence.EvidenceBundle{OperandPageProofs: p.KeyPageProofs}
	pages, err := verifiedKeyPages(b, o)
	if err != nil {
		t.Fatalf("the committed page proofs as operand pages: %v", err)
	}
	if !pages[strings.ToLower(accPage)] {
		t.Fatalf("the proven pages %v miss %s", pages, accPage)
	}
	c := &policyeval.ProvenRolesContext{ProvenPages: pages}
	if v, err := c.ResolveOperand(policyeval.OpActorHasKey, []string{accPage}); err != nil || v != policyeval.TruthOperand(true) {
		t.Fatalf("actor::has_key(%s) = %v, %v; want 1", accPage, v, err)
	}
	if v, err := c.ResolveOperand(policyeval.OpActorHasKey, []string{accPage + "-unproven"}); err == nil {
		t.Fatalf("actor::has_key of an unproven page answered %v", v)
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
