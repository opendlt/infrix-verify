package verifykit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/stateroot"
)

type fakeAnchors struct {
	entries map[string]stateroot.AnchorEntry
	err     error
}

func (f fakeAnchors) AnchorAt(_ context.Context, tx string) (stateroot.AnchorEntry, error) {
	if f.err != nil {
		return stateroot.AnchorEntry{}, f.err
	}
	e, ok := f.entries[tx]
	if !ok {
		return stateroot.AnchorEntry{}, errors.New("no such transaction")
	}
	return e, nil
}

// provenCase is a document that PASSES, with the bundle root and consumer id it is for and the L0 that backs it. It is read from the shared vectors of package
// stateroot (the one file that pins this implementation to the runtime's), so this package builds no tree: it only proves that Verify wires the check, the bundle's
// own outcome id, the reader and the requirement flag through. The tree arithmetic and every tamper case are pinned in package stateroot.
type provenCase struct {
	doc       *stateroot.Document
	root      [32]byte
	outcomeID string
	l0        fakeAnchors
}

func provenCaseFromVectors(t *testing.T) provenCase {
	t.Helper()
	return caseFromVectors(t, "a proven leaf recorded in the gap of a delayed anchor passes", "pass")
}

// caseFromVectors is the shared vectors' document case of that name (which must carry that verdict), with the bundle root, consumer id and L0 it is judged against.
func caseFromVectors(t *testing.T, name, verdict string) provenCase {
	t.Helper()
	raw, err := os.ReadFile("../stateroot/testdata/state-root-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Documents []struct {
			Name       string          `json:"name"`
			Document   json.RawMessage `json:"document"`
			BundleRoot string          `json:"bundleRoot"`
			ConsumerID string          `json:"consumerId"`
			Verdict    string          `json:"verdict"`
			Anchors    map[string]struct {
				Roots       []string `json:"roots"`
				FirstHeight uint64   `json:"firstHeight"`
				LastHeight  uint64   `json:"lastHeight"`
			} `json:"anchors"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	for _, c := range vf.Documents {
		if c.Name != name || c.Verdict != verdict {
			continue
		}
		pc := provenCase{doc: &stateroot.Document{}, outcomeID: c.ConsumerID, l0: fakeAnchors{entries: map[string]stateroot.AnchorEntry{}}}
		if err := json.Unmarshal(c.Document, pc.doc); err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(c.BundleRoot)
		if err != nil || len(b) != 32 {
			t.Fatalf("bundleRoot: %v", err)
		}
		copy(pc.root[:], b)
		for tx, a := range c.Anchors {
			e := stateroot.AnchorEntry{FirstHeight: a.FirstHeight, LastHeight: a.LastHeight}
			for _, r := range a.Roots {
				h, err := hex.DecodeString(r)
				if err != nil || len(h) != 32 {
					t.Fatalf("anchor root: %v", err)
				}
				var r32 [32]byte
				copy(r32[:], h)
				e.Roots = append(e.Roots, r32)
			}
			pc.l0.entries[tx] = e
		}
		return pc
	}
	t.Fatalf("the vectors have no case %q with verdict %s", name, verdict)
	return provenCase{}
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

func TestAProvenStateRootBoundToTheBundleAndDatedPassesAndRaisesNoLevel(t *testing.T) {
	pc := provenCaseFromVectors(t)
	pkg := buildPortableFor(t, true, pc.root, pc.outcomeID)
	base := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckPass || !strings.Contains(c.Detail, "inside the span") {
		t.Fatalf("a proven, bound, dated root: %+v", c)
	}
	sameVerdict(t, base, r) // no level moved, and nothing that verified stopped verifying
}

func TestAForgedStateRootMakesTheBundleNotVerified(t *testing.T) {
	pc := provenCaseFromVectors(t)
	pkg := buildPortableFor(t, true, [32]byte{0xde, 0xad}, pc.outcomeID) // a proof for a root the bundle does not carry
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "the proof is for state root") {
		t.Fatalf("a proof for another root: %+v", c)
	}
	if r.Verified || r.CryptographicallyVerified || r.FullyVerified {
		t.Fatalf("a forged root left the bundle verified=%v crypto=%v full=%v", r.Verified, r.CryptographicallyVerified, r.FullyVerified)
	}
}

// THE BINDING: a leaf the node recorded for ANOTHER bundle's outcome proves the node held that root, not that this bundle read it. It is refused, and a bundle that
// names no outcome id cannot be bound at all and is unchecked.
func TestAProofRecordedForAnotherOutcomeIsRefusedAndABundleWithNoOutcomeIdIsUnchecked(t *testing.T) {
	pc := provenCaseFromVectors(t)
	other := buildPortableFor(t, true, pc.root, pc.outcomeID+"-other")
	r := Verify(context.Background(), other, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "is not this bundle's") || r.Verified {
		t.Fatalf("a leaf recorded for another outcome: %+v verified=%v", c, r.Verified)
	}
	anon := buildPortableFor(t, true, pc.root, "")
	r = Verify(context.Background(), anon, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckSkip || !strings.Contains(c.Detail, "no consumer to bind") || !r.Verified {
		t.Fatalf("a bundle with no outcome id: %+v verified=%v", c, r.Verified)
	}
}

func TestASealL0NeverAnchoredMakesTheBundleNotVerifiedAndNoEndpointIsASkip(t *testing.T) {
	pc := provenCaseFromVectors(t)
	pkg := buildPortableFor(t, true, pc.root, pc.outcomeID)
	unlisted := fakeAnchors{entries: map[string]stateroot.AnchorEntry{}}
	for tx, e := range pc.l0.entries {
		unlisted.entries[tx] = stateroot.AnchorEntry{Roots: [][32]byte{{1}, {2}}, FirstHeight: e.FirstHeight, LastHeight: e.LastHeight}
	}
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: unlisted})
	if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "never anchored") || r.Verified {
		t.Fatalf("a seal L0 does not list: %+v verified=%v", c, r.Verified)
	}
	r = Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc}) // no reader: no endpoint
	if c := stateRootCheck(t, r); c.Status != CheckSkip || !strings.Contains(c.Detail, "no L0 endpoint was supplied") || !r.Verified {
		t.Fatalf("a consistent proof with no endpoint: %+v verified=%v", c, r.Verified)
	}
}

// the window rules reach the verdict through Verify: a leaf dated outside the span the anchors enclose fails the bundle
func TestALeafOutsideTheAnchoredSpanMakesTheBundleNotVerified(t *testing.T) {
	pc := provenCaseFromVectors(t)
	pkg := buildPortableFor(t, true, pc.root, pc.outcomeID)
	late := *pc.doc
	late.LeafHeight = 10_000 // far after the covering window; the proof's leaf hash covers the height too, so the proof no longer computes
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: &late, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckFail || r.Verified {
		t.Fatalf("a rewritten leaf height: %+v verified=%v", c, r.Verified)
	}
	// the covering entry with its window removed leaves the height undated: a skip, never a pass
	undated := fakeAnchors{entries: map[string]stateroot.AnchorEntry{}}
	for tx, e := range pc.l0.entries {
		undated.entries[tx] = stateroot.AnchorEntry{Roots: e.Roots}
	}
	r = Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: undated})
	if c := stateRootCheck(t, r); c.Status != CheckSkip || !strings.Contains(c.Detail, "undated") {
		t.Fatalf("an entry with no window: %+v", c)
	}
}

func TestRequiringAProvenStateRootTurnsEverySkipIntoAFailure(t *testing.T) {
	pc := provenCaseFromVectors(t)
	pkg := buildPortableFor(t, true, pc.root, pc.outcomeID)
	awaiting := &stateroot.Document{Version: stateroot.DocumentVersion, Status: stateroot.StatusAwaitingAnchor, StateRoot: pc.doc.StateRoot, CurrentSize: 3, NewestAnchoredSize: 1}
	v1 := *pc.doc
	v1.Version = "infrix-state-root-proof-v1"
	for name, opts := range map[string]Options{
		"no document":        {},
		"awaiting an anchor": {StateRootProof: awaiting, StateRootAnchors: pc.l0},
		"no endpoint":        {StateRootProof: pc.doc},
		"a version 1 proof":  {StateRootProof: &v1, StateRootAnchors: pc.l0},
	} {
		opts.L0Confirmer, opts.RequireStateRootProof = okConfirmer(), true
		r := Verify(context.Background(), pkg, opts)
		if c := stateRootCheck(t, r); c.Status != CheckFail || !strings.Contains(c.Detail, "a proven state root is required") || r.Verified {
			t.Fatalf("%s, required: %+v verified=%v", name, c, r.Verified)
		}
	}
	// and a proven one still passes when required
	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0, RequireStateRootProof: true})
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

// THE CHECKPOINT STATEMENT reaches the verdict through Verify: a node that checkpointed its root history answers a bundle recorded before the checkpoint with an unavailable
// document that carries the statement. A false statement fails the bundle; a true one is a skip (it proves nothing about the bundle), leaves every level and verdict where
// they were, and a verifier that requires a proven root refuses it.
func flippedCheckpoint(t *testing.T, d *stateroot.Document) *stateroot.Document {
	t.Helper()
	c := *d
	ck := *d.Checkpoint
	ck.Compact = append([]string(nil), d.Checkpoint.Compact...)
	b, err := hex.DecodeString(ck.Compact[0])
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	ck.Compact[0] = hex.EncodeToString(b)
	c.Checkpoint = &ck
	return &c
}

func TestAFalseCheckpointStatementMakesTheBundleNotVerifiedAndATrueOneLeavesItUnchecked(t *testing.T) {
	pc := caseFromVectors(t, "an unavailable proof whose checkpoint L0 confirms is a skip saying so", "skip")
	if pc.doc.Status != stateroot.StatusUnavailable || pc.doc.Checkpoint == nil {
		t.Fatalf("premise: the case is not an unavailable document that states a checkpoint: %+v", pc.doc)
	}
	pkg := buildPortableFor(t, true, pc.root, pc.outcomeID)
	base := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer()})

	r := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, r); c.Status != CheckSkip || !strings.Contains(c.Detail, "L0 lists that seal in anchor transaction cc33") || !r.Verified {
		t.Fatalf("a true statement L0 confirms: %+v verified=%v", c, r.Verified)
	}
	sameVerdict(t, base, r) // no level moved, and nothing that verified stopped verifying

	off := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc})
	if c := stateRootCheck(t, off); c.Status != CheckSkip || !strings.Contains(c.Detail, "no L0 endpoint was supplied") || !off.Verified {
		t.Fatalf("a true statement with no endpoint: %+v verified=%v", c, off.Verified)
	}

	bad := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: flippedCheckpoint(t, pc.doc), StateRootAnchors: pc.l0})
	if c := stateRootCheck(t, bad); c.Status != CheckFail || !strings.Contains(c.Detail, "the statement is false") || bad.Verified || bad.CryptographicallyVerified || bad.FullyVerified {
		t.Fatalf("a false statement: %+v verified=%v crypto=%v full=%v", c, bad.Verified, bad.CryptographicallyVerified, bad.FullyVerified)
	}
	badOffline := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: flippedCheckpoint(t, pc.doc)})
	if c := stateRootCheck(t, badOffline); c.Status != CheckFail || badOffline.Verified {
		t.Fatalf("a false statement needs no endpoint to be refused: %+v verified=%v", c, badOffline.Verified)
	}

	unlisted := fakeAnchors{entries: map[string]stateroot.AnchorEntry{}}
	for tx, e := range pc.l0.entries {
		unlisted.entries[tx] = stateroot.AnchorEntry{Roots: [][32]byte{{1}, {2}}, FirstHeight: e.FirstHeight, LastHeight: e.LastHeight}
	}
	never := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: unlisted})
	if c := stateRootCheck(t, never); c.Status != CheckFail || !strings.Contains(c.Detail, "never anchored") || never.Verified {
		t.Fatalf("a seal L0 never listed: %+v verified=%v", c, never.Verified)
	}
	down := Verify(context.Background(), pkg, Options{L0Confirmer: okConfirmer(), StateRootProof: pc.doc, StateRootAnchors: fakeAnchors{err: errors.New("connection refused")}})
	if c := stateRootCheck(t, down); c.Status != CheckFail || !strings.Contains(c.Detail, "could not read the checkpoint's anchor from L0") || down.Verified {
		t.Fatalf("an unreadable anchor: %+v verified=%v", c, down.Verified)
	}

	// a verifier that requires a proven root refuses a true statement too: it proves nothing about the bundle
	for name, opts := range map[string]Options{
		"confirmed": {StateRootProof: pc.doc, StateRootAnchors: pc.l0},
		"offline":   {StateRootProof: pc.doc},
	} {
		opts.L0Confirmer, opts.RequireStateRootProof = okConfirmer(), true
		req := Verify(context.Background(), pkg, opts)
		if c := stateRootCheck(t, req); c.Status != CheckFail || !strings.Contains(c.Detail, "a proven state root is required") || req.Verified {
			t.Fatalf("%s, required: %+v verified=%v", name, c, req.Verified)
		}
	}
}
