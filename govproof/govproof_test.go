// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/internal/tamper"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// fixture is the SIMULATOR governance fixture (testdata/simulator/provenance.json): verified only against its own pin passed explicitly, never a Kermit
// claim.
type fixture struct {
	Execution govproof.GovernanceExecution   `json:"execution"`
	Expect    govproof.GovernanceExpectation `json:"expect"`
	Pin       consensus.Pin                  `json:"pin"`
	Signers   []l0proof.Bytes                `json:"signerPublicKeys"`
	Outsider  l0proof.Bytes                  `json:"outsiderSignature"`
	OtherPage govproof.KeyPageProof          `json:"otherPage"`
	LaterPage govproof.KeyPageProof          `json:"laterPage"`
}

func load(t testing.TB) *fixture {
	b, err := os.ReadFile(filepath.Join("testdata", "simulator", "governance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func (f *fixture) opts() l0proof.Options { return l0proof.Options{OverridePin: &f.Pin} }

func mustFail(t *testing.T, r govproof.GovernanceResult, want string) {
	t.Helper()
	if r.Verified {
		t.Fatalf("verified; want a refusal naming %q", want)
	}
	if !strings.Contains(r.Reason, want) {
		t.Fatalf("refused for %q; want the refusal to name %q", r.Reason, want)
	}
}

// PV-G2-01: an M-of-N multi-signature Accumulate accepted, its inclusion proven to a certified Directory root, with the page proven at the executing block
// and the threshold computed from the proven page.
func TestPV_G2_01_AnAcceptedMultiSigIsProven(t *testing.T) {
	f := load(t)
	r := govproof.VerifyGovernance(&f.Execution, f.Expect, f.opts())
	if !r.Verified {
		t.Fatalf("the governance execution does not verify: %s", r.Reason)
	}
	if r.Signers != 2 || r.Threshold != 2 || r.Height != f.Execution.Page.Height {
		t.Fatalf("signers %d threshold %d height %d", r.Signers, r.Threshold, r.Height)
	}
}

// PV-G1-02: each approver key is proven on its page at the signing height; a key not on the page is not.
func TestPV_G1_02_EachApproverKeyIsProvenOnItsPage(t *testing.T) {
	f := load(t)
	kp := govproof.VerifyKeyPage(&f.Execution.Page, f.opts())
	if !kp.Verified {
		t.Fatalf("the page proof does not verify: %s", kp.Reason)
	}
	if kp.Height != f.Execution.Page.Height || kp.Page.AcceptThreshold != 2 || len(kp.Page.KeyHashes) != 3 {
		t.Fatalf("page %+v at %d", kp.Page, kp.Height)
	}
	for i, k := range f.Signers {
		h := sha256.Sum256(k)
		if !kp.Page.Has(h[:]) {
			t.Fatalf("approver %d's key is not proven on the page", i)
		}
	}
	h := sha256.Sum256([]byte("not a key"))
	if kp.Page.Has(h[:]) {
		t.Fatal("an arbitrary hash is reported on the page")
	}
	// the height label must be the proven block
	bad := f.Execution.Page
	bad.Height++
	if r := govproof.VerifyKeyPage(&bad, f.opts()); r.Verified || !strings.Contains(r.Reason, "labelled height") {
		t.Fatalf("a mislabelled height was not refused: %+v", r)
	}
	// the verifier's own pin, never the proof's: with no override the compiled Kermit pin refuses a simulator proof
	if r := govproof.VerifyKeyPage(&f.Execution.Page, l0proof.Options{Network: l0proof.NetworkKermit}); r.Verified || !strings.Contains(r.Reason, "not the verifier's pin") {
		t.Fatalf("a simulator page proof was accepted under the Kermit pin: %+v", r)
	}
}

// BD-03: a governance transaction for a different plan, bundle or account fails.
func TestBD_03_AGovernanceTxForSomethingElseFails(t *testing.T) {
	f := load(t)
	e := f.Expect
	e.PlanHash[0] ^= 1
	mustFail(t, govproof.VerifyGovernance(&f.Execution, e, f.opts()), "does not carry exactly the approval")
	e = f.Expect
	e.BundleID += "-other"
	mustFail(t, govproof.VerifyGovernance(&f.Execution, e, f.opts()), "does not carry exactly the approval")
	e = f.Expect
	e.Account = strings.Replace(e.Account, "governance", "elsewhere", 1)
	mustFail(t, govproof.VerifyGovernance(&f.Execution, e, f.opts()), "not the anchor account")
	e = f.Expect
	e.Page = strings.Replace(e.Page, "book/1", "book/2", 1)
	mustFail(t, govproof.VerifyGovernance(&f.Execution, e, f.opts()), "not the governance page")
}

// BD-04: a key-page proof for a different page, or for a height after the signatures, fails.
func TestBD_04_APageProofForAnotherPageOrALaterHeightFails(t *testing.T) {
	f := load(t)
	if r := govproof.VerifyKeyPage(&f.OtherPage, f.opts()); !r.Verified {
		t.Fatalf("the other page's proof must verify on its own (so the refusal below is the binding): %s", r.Reason)
	}
	if r := govproof.VerifyKeyPage(&f.LaterPage, f.opts()); !r.Verified || r.Height <= f.Execution.Page.Height {
		t.Fatalf("the later page proof must verify on its own at a later height: %+v", r)
	}
	g := f.Execution
	g.Page = f.OtherPage
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "not the governance page")
	g = f.Execution
	g.Page = f.LaterPage
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "not at the block that executed the transaction")
}

// The threshold is computed from the proven page: fewer distinct keys than its accept threshold, a repeated signature, or a key not on the page fails.
func TestGovernanceThresholdComesFromTheProvenPage(t *testing.T) {
	f := load(t)
	g := f.Execution
	g.Signatures = g.Signatures[:1]
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "the proven page requires 2")
	g = f.Execution
	g.Signatures = []l0proof.Bytes{f.Execution.Signatures[0], f.Execution.Signatures[0]}
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "canonical order")
	g = f.Execution
	g.Signatures = []l0proof.Bytes{f.Execution.Signatures[1], f.Execution.Signatures[0]}
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "canonical order")
	g = f.Execution
	g.Signatures = []l0proof.Bytes{f.Execution.Signatures[0], f.Outsider}
	if bytes.Compare(g.Signatures[0], g.Signatures[1]) > 0 {
		g.Signatures[0], g.Signatures[1] = g.Signatures[1], g.Signatures[0]
	}
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "is not on the proven page")
	g = f.Execution
	g.TxHash = append(l0proof.Bytes(nil), g.TxHash...)
	g.TxHash[0] ^= 1
	mustFail(t, govproof.VerifyGovernance(&g, f.Expect, f.opts()), "labelled tx")
}

func cloneExec(t *testing.T, g *govproof.GovernanceExecution) *govproof.GovernanceExecution {
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var c govproof.GovernanceExecution
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func same(t *testing.T, a, b any) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(bytes.ReplaceAll(ja, []byte("null"), []byte("[]")), bytes.ReplaceAll(jb, []byte("null"), []byte("[]")))
}

// TS-ALL for the governance execution (and so for its key-page proof, its receipt chain and every accepted signature): every mutation of every field that
// changes the execution makes it fail, and the census requires every field path of the TYPE to have had an effective mutation.
func TestTSALL_EveryFieldOfTheGovernanceExecutionIsTamperEvident(t *testing.T) {
	f := load(t)
	g := cloneExec(t, &f.Execution)
	before := cloneExec(t, g)
	var ms []tamper.Mutation
	tamper.Mutations(reflect.ValueOf(g).Elem(), "", &ms)
	covered := map[string]bool{}
	total := 0
	for _, m := range ms {
		m.Apply()
		if !same(t, g, before) {
			if r := govproof.VerifyGovernance(g, f.Expect, f.opts()); r.Verified {
				t.Errorf("%s of %s still verifies", m.Kind, m.Path)
			}
			covered[tamper.TypePath(m.Path)] = true
			total++
		}
		m.Undo()
		if !reflect.DeepEqual(g, before) {
			t.Fatalf("undoing %s of %s did not restore the execution", m.Kind, m.Path)
		}
	}
	if r := govproof.VerifyGovernance(g, f.Expect, f.opts()); !r.Verified {
		t.Fatalf("the restored execution no longer verifies: %s", r.Reason)
	}
	// the execution's page is the ledger form, which carries no partition anchor (directoryroot.go): a partition anchor present in it, in any field
	// and under every mutation, makes the execution fail, because a key-page proof takes one form
	pa := loadDirRoot(t).OtherAnchor
	g.Page.PartitionAnchor = &pa
	if r := govproof.VerifyGovernance(g, f.Expect, f.opts()); r.Verified {
		t.Fatal("a ledger-form page carrying a partition anchor still verifies")
	}
	covered["Page.PartitionAnchor"] = true
	var pms []tamper.Mutation
	tamper.Mutations(reflect.ValueOf(g.Page.PartitionAnchor).Elem(), "Page.PartitionAnchor", &pms)
	for _, m := range pms {
		m.Apply()
		if r := govproof.VerifyGovernance(g, f.Expect, f.opts()); r.Verified {
			t.Errorf("%s of %s on a ledger-form page still verifies", m.Kind, m.Path)
		}
		covered[tamper.TypePath(m.Path)] = true
		total++
		m.Undo()
	}
	g.Page.PartitionAnchor = nil
	if miss := tamper.Missing(reflect.TypeOf(govproof.GovernanceExecution{}), covered); len(miss) > 0 {
		t.Fatalf("the census found %d field(s) with no effective mutation: %s", len(miss), strings.Join(miss, ", "))
	}
	t.Logf("%d mutations over %d field paths, every one refused", total, len(covered))
}

// FZ-01 for this package's decoders and verifiers: an arbitrary JSON execution never panics and never verifies unless it is the fixture itself.
func FuzzVerifyGovernance(f *testing.F) {
	fx := load(f)
	seed, err := json.Marshal(fx.Execution)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var g govproof.GovernanceExecution
		if json.Unmarshal(data, &g) != nil {
			return
		}
		r := govproof.VerifyGovernance(&g, fx.Expect, fx.opts())
		if r.Verified && !same(t, &g, &fx.Execution) {
			// a different encoding of the same execution may verify; anything else must not
			var ref govproof.GovernanceExecution
			if json.Unmarshal(seed, &ref) != nil || !reflect.DeepEqual(&g, &ref) {
				t.Fatalf("a changed execution verified")
			}
		}
		kp := govproof.VerifyKeyPage(&g.Page, fx.opts())
		if kp.Verified && !reflect.DeepEqual(g.Page, fx.Execution.Page) && !reflect.DeepEqual(g.Page, fx.OtherPage) && !reflect.DeepEqual(g.Page, fx.LaterPage) {
			t.Fatalf("a changed key-page proof verified")
		}
	})
}

// A signature whose value no longer verifies over the transaction fails, even with every other field intact: the verifier checks each accepted signature
// itself and never counts one because Accumulate recorded it.
func TestAForgedSignatureValueFails(t *testing.T) {
	f := load(t)
	g := cloneExec(t, &f.Execution)
	raw := g.Signatures[0]
	// the value is field 3: tag 0x03, length 0x40, 64 bytes
	i := bytes.Index(raw, []byte{0x03, 0x40})
	if i < 0 {
		t.Fatal("the fixture signature has no 64-byte value field")
	}
	raw[i+2+10] ^= 1
	mustFail(t, govproof.VerifyGovernance(g, f.Expect, f.opts()), "does not verify over the transaction")
}
