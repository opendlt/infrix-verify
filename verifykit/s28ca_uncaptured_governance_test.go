package verifykit

import (
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
)

// An approval the node executed on Accumulate whose governance page proof was lost with its capture window is NAMED by the governance check and
// credited nothing (main's ruling 2026-11-26: the bundle claims exactly what was captured).
func TestS28caAnUncapturedGovernancePageIsNamedAndNotCredited(t *testing.T) {
	b := &evidence.EvidenceBundle{ID: "ev-i", UncapturedProofs: []evidence.UncapturedProof{{
		Kind: evidence.UncapturedGovernancePage, Subject: "acc://gov.acme/book/1", TxHash: "ab12", Height: 42, Reason: "the node restarted after the executing block",
	}}}
	r := &Report{}
	if r.checkGovernanceExecution(b, [32]byte{1}, true, Options{GovernanceAccount: "acc://gov.acme/governance", GovernancePage: "acc://gov.acme/book/1"}) {
		t.Fatal("a bundle with no governance execution was credited one")
	}
	if len(r.Checks) != 1 || r.Checks[0].Status != CheckSkip || !strings.Contains(r.Checks[0].Detail, "acc://gov.acme/book/1 at block 42 of tx ab12") ||
		!strings.Contains(r.Checks[0].Detail, "uncaptured") {
		t.Fatalf("the governance check did not name the uncaptured page proof: %+v", r.Checks)
	}
	r = &Report{}
	r.checkGovernanceExecution(&evidence.EvidenceBundle{ID: "ev-j"}, [32]byte{1}, true, Options{})
	if strings.Contains(r.Checks[0].Detail, "uncaptured") {
		t.Fatalf("a bundle naming nothing uncaptured was reported with an uncaptured proof: %+v", r.Checks)
	}
}
