package verifykit

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/stateroot"
)

type fakeAnchors struct {
	roots map[string][][32]byte
	err   error
}

func (f fakeAnchors) RootsAt(_ context.Context, tx string) ([][32]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	r, ok := f.roots[tx]
	if !ok {
		return nil, errors.New("no such transaction")
	}
	return r, nil
}

// rootProofFor makes the document for a one-leaf history whose only leaf is the bundle's own state root, and the L0 that lists its seal: the smallest history a
// proof can be made against, which is enough to exercise the integration (the tree arithmetic is pinned by the shared vectors in package stateroot).
func rootProofFor(t *testing.T, root [32]byte) (*stateroot.Document, fakeAnchors) {
	t.Helper()
	sealed, err := stateroot.SealedRootOf(0, 1, 77, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := &stateroot.Document{
		Version:         stateroot.DocumentVersion,
		Status:          stateroot.StatusProven,
		StateRoot:       hex.EncodeToString(root[:]),
		LeafHeight:      77,
		LeafIndex:       0,
		TreeSize:        1,
		AccumulatorRoot: hex.EncodeToString(sealed[:]),
		Anchor:          &stateroot.AnchorRef{TxHash: "ab12"},
	}
	return doc, fakeAnchors{roots: map[string][][32]byte{"ab12": {{1}, sealed}}}
}

func stateRootCheck(t *testing.T, r *Report) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == stateroot.CheckName {
			return c
		}
	}
	t.Fatalf("the report has no %s check: %+v", stateroot.CheckName, r.Checks)
	return Check{}
}

func sameVerdict(t *testing.T, a, b *Report) {
	t.Helper()
	if a.Verified != b.Verified || a.ProofLevel != b.ProofLevel || a.GovernanceLevel != b.GovernanceLevel || a.Tier != b.Tier ||
		a.AssuranceClass != b.AssuranceClass || a.CryptographicallyVerified != b.CryptographicallyVerified || a.FullyVerified != b.FullyVerified ||
		a.L0Verified != b.L0Verified {
		t.Fatalf("the verdicts differ:\n%+v\n%+v", a, b)
	}
}

// A bundle with no state root document (every bundle exported before the node kept a root history) is judged exactly as before: the one difference is a skip that
// says its state root is unchecked and why.
func TestAStateRootCheckWithNoDocumentIsASkipAndNoVerdictMoves(t *testing.T) {
	pkg := buildPortable(t, true)
	with := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})
	c := stateRootCheck(t, with)
	if c.Status != CheckSkip || !strings.Contains(c.Detail, "no state root proof is attached") {
		t.Fatalf("with no document the check is %+v", c)
	}
	if !with.Verified {
		t.Fatalf("premise: the bundle does not verify: %+v", with.Checks)
	}
	// the same report with the new check removed is what the verifier said before the check existed
	var without Report = *with
	without.Checks = nil
	for _, ch := range with.Checks {
		if ch.Name != stateroot.CheckName {
			without.Checks = append(without.Checks, ch)
		}
	}
	if len(without.Checks) != len(with.Checks)-1 {
		t.Fatal("the state root check appeared more than once")
	}
	sameVerdict(t, with, &without)
}

func TestAProvenStateRootPassesAndRaisesNoLevel(t *testing.T) {
	pkg := buildPortable(t, true)
	base := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})
	doc, l0 := rootProofFor(t, [32]byte{7})
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: doc, StateRootAnchors: l0})
	if c := stateRootCheck(t, r); c.Status != CheckPass {
		t.Fatalf("a proven root: %+v", c)
	}
	sameVerdict(t, base, r) // no level moved, and nothing that verified stopped verifying
}

func TestAForgedStateRootMakesTheBundleNotVerified(t *testing.T) {
	pkg := buildPortable(t, true)
	doc, l0 := rootProofFor(t, [32]byte{0xde, 0xad}) // a proof for a root the bundle does not carry
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: doc, StateRootAnchors: l0})
	if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "the proof is for state root") {
		t.Fatalf("a proof for another root: %+v", c)
	}
	if r.Verified || r.CryptographicallyVerified || r.FullyVerified {
		t.Fatalf("a forged root left the bundle verified=%v crypto=%v full=%v", r.Verified, r.CryptographicallyVerified, r.FullyVerified)
	}
}

func TestASealL0NeverAnchoredMakesTheBundleNotVerifiedAndNoEndpointIsASkip(t *testing.T) {
	pkg := buildPortable(t, true)
	doc, _ := rootProofFor(t, [32]byte{7})
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: doc, StateRootAnchors: fakeAnchors{roots: map[string][][32]byte{"ab12": {{1}, {2}}}}})
	if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "never anchored") || r.Verified {
		t.Fatalf("a seal L0 does not list: %+v verified=%v", c, r.Verified)
	}
	r = Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: doc}) // no reader: no endpoint
	if c := stateRootCheck(t, r); c.Status != CheckSkip || !strings.Contains(c.Detail, "no L0 endpoint was supplied") || !r.Verified {
		t.Fatalf("a consistent proof with no endpoint: %+v verified=%v", c, r.Verified)
	}
}

func TestRequiringAProvenStateRootTurnsEverySkipIntoAFailure(t *testing.T) {
	pkg := buildPortable(t, true)
	doc, l0 := rootProofFor(t, [32]byte{7})
	awaiting := &stateroot.Document{Version: stateroot.DocumentVersion, Status: stateroot.StatusAwaitingAnchor, StateRoot: doc.StateRoot, CurrentSize: 3, NewestAnchoredSize: 1}
	for name, opts := range map[string]Options{
		"no document":        {},
		"awaiting an anchor": {StateRootProof: awaiting, StateRootAnchors: l0},
		"no endpoint":        {StateRootProof: doc},
	} {
		opts.L0Confirmer, opts.RequireStateRootProof = okConfirmer(), true
		r := Verify(context.Background(), pkg, opts)
		if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "a proven state root is required") || r.Verified {
			t.Fatalf("%s, required: %+v verified=%v", name, c, r.Verified)
		}
	}
	// and a proven one still passes when required
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: doc, StateRootAnchors: l0, RequireStateRootProof: true})
	if c := stateRootCheck(t, r); c.Status != CheckPass || !r.Verified {
		t.Fatalf("a proven root, required: %+v verified=%v", c, r.Verified)
	}
}

func TestADocumentThatDidNotDecodeFailsTheBundle(t *testing.T) {
	pkg := buildPortable(t, true)
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProofError: "the stateRootProof attached to the bundle does not decode"})
	if c := stateRootCheck(t, r); c.Status != CheckFail || r.Verified {
		t.Fatalf("a malformed document: %+v verified=%v", c, r.Verified)
	}
}
