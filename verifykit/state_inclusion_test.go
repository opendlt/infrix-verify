// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"crypto/sha256"
	"sort"
	"testing"

	evidence "github.com/opendlt/infrix-schema/evidence"
)

// brief 28bd phase 2b (L2992): L1 and L2 from state proofs this verifier recomputes; integrity a precondition of every level.
// Native proof plan IDs: PV-INT-01, PV-L1-01, PV-L2-01, BD-05 (state), FZ-02 (monotone), FZ-03 (deterministic).

// testContract is one contract's committed state for the test-side tree builder (the node's builder is held to the verifier by the
// differential test in infrix-core).
type testContract struct {
	url  string
	kv   map[string][]byte
	keys []string
}

func newTestContract(url string, kv map[string][]byte) testContract {
	c := testContract{url: url, kv: kv}
	for k := range kv {
		c.keys = append(c.keys, k)
	}
	sort.Strings(c.keys)
	return c
}

func (c testContract) leaves() [][32]byte {
	out := make([][32]byte, len(c.keys))
	for i, k := range c.keys {
		out[i] = stateLeafHash(k, c.kv[k])
	}
	return out
}

func stateLevelUp(level [][32]byte) [][32]byte {
	next := make([][32]byte, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 == len(level) {
			next = append(next, stateNodeHash(level[i], level[i]))
			continue
		}
		next = append(next, stateNodeHash(level[i], level[i+1]))
	}
	return next
}

func (c testContract) root() [32]byte {
	level := c.leaves()
	for len(level) > 1 {
		level = stateLevelUp(level)
	}
	return level[0]
}

func (c testContract) prove(key string) evidence.StorageInclusionProof {
	idx := sort.SearchStrings(c.keys, key)
	level := c.leaves()
	var path [][32]byte
	for len(level) > 1 {
		sib := idx ^ 1
		if sib >= len(level) {
			sib = idx
		}
		path = append(path, level[sib])
		level = stateLevelUp(level)
		idx /= 2
	}
	return evidence.StorageInclusionProof{Contract: c.url, Key: key, Value: c.kv[key], KeyPath: path, ContractRoot: c.root()}
}

// testNodeTree builds the sealed node state root over contracts (sorted by url) and proves one.
func testNodeTree(cs []testContract) (root [32]byte, prove func(url string) evidence.AccountInclusionProof) {
	sorted := append([]testContract(nil), cs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].url < sorted[j].url })
	var levels [][][32]byte
	level := make([][32]byte, len(sorted))
	for i, c := range sorted {
		level[i] = nodeTreeLeafHash(c.url, c.root())
	}
	levels = append(levels, level)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeTreeNodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		levels = append(levels, next)
		level = next
	}
	root = nodeTreeSeal(uint64(len(sorted)), level[0])
	prove = func(url string) evidence.AccountInclusionProof {
		idx := -1
		for i, c := range sorted {
			if c.url == url {
				idx = i
			}
		}
		p := evidence.AccountInclusionProof{Contract: url, ContractRoot: sorted[idx].root(), Index: uint64(idx), Leaves: uint64(len(sorted))}
		i := idx
		for lvl := 0; lvl < len(levels)-1; lvl++ {
			l := levels[lvl]
			if i%2 == 1 {
				p.Siblings = append(p.Siblings, l[i-1])
			} else if i+1 < len(l) {
				p.Siblings = append(p.Siblings, l[i+1])
			}
			i /= 2
		}
		return p
	}
	return root, prove
}

// stateFixture: three contracts; the bundle claims two keys of the escrow contract.
func stateFixture() (stateRoot [32]byte, storage []evidence.StorageInclusionProof, account []evidence.AccountInclusionProof, escrow testContract) {
	escrow = newTestContract("acc://app.acme/escrow", map[string][]byte{"balance": {0, 0, 1, 0}, "released": {1}, "approver:1": []byte("acc://a.acme"), "approver:2": []byte("acc://b.acme"), "nonce": {7}})
	other := newTestContract("acc://app.acme/token", map[string][]byte{"supply": {9}})
	third := newTestContract("acc://zed.acme/counter", map[string][]byte{"count": {3}, "owner": []byte("z")})
	root, prove := testNodeTree([]testContract{escrow, other, third})
	return root, []evidence.StorageInclusionProof{escrow.prove("balance"), escrow.prove("released")}, []evidence.AccountInclusionProof{prove(escrow.url)}, escrow
}

func verifyState(t *testing.T, anchored bool, stateRoot [32]byte, mutate func(*evidence.EvidenceBundle)) *Report {
	t.Helper()
	pkg := buildPortableWith(t, anchored, stateRoot, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		if mutate != nil {
			mutate(b)
		}
	})
	return Verify(context.Background(), pkg, Options{})
}

// PV-L2-01 / PV-L1-01: each key in its contract root and the contract root in the bundle's state root reach L2; the keys alone reach L1.
func TestStateProofsReachL1AndL2(t *testing.T) {
	root, storage, account, _ := stateFixture()
	r := verifyState(t, false, root, func(b *evidence.EvidenceBundle) { b.StorageProofs, b.AccountProofs = storage, account })
	if r.ProofLevel != "L2" || !r.Verified || checkStatus(r, "state_inclusion") != CheckPass {
		t.Fatalf("keys + account inclusion: proof %s verified %v (%+v); want a verified L2", r.ProofLevel, r.Verified, r.Checks)
	}
	r = verifyState(t, false, root, func(b *evidence.EvidenceBundle) { b.StorageProofs = storage })
	if r.ProofLevel != "L1" || !r.Verified {
		t.Fatalf("keys alone: proof %s verified %v; want a verified L1", r.ProofLevel, r.Verified)
	}
	// with a valid anchor inclusion as well, the highest rung is L3
	r = verifyState(t, true, root, func(b *evidence.EvidenceBundle) { b.StorageProofs, b.AccountProofs = storage, account })
	if r.ProofLevel != "L3" {
		t.Fatalf("state proofs + anchor inclusion: proof %s, want L3", r.ProofLevel)
	}
}

// PV-L2-01's binding bite: an account leaf embedding a DIFFERENT storage root fails, and so does every other tampered state proof.
func TestStateProofsRefuseEveryTamper(t *testing.T) {
	root, storage, account, escrow := stateFixture()
	clone := func() ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
		s := make([]evidence.StorageInclusionProof, len(storage))
		for i, p := range storage {
			p.KeyPath = append([][32]byte(nil), p.KeyPath...)
			p.Value = append([]byte(nil), p.Value...)
			s[i] = p
		}
		a := make([]evidence.AccountInclusionProof, len(account))
		for i, p := range account {
			p.Siblings = append([][32]byte(nil), p.Siblings...)
			a[i] = p
		}
		return s, a
	}
	other := newTestContract("acc://app.acme/escrow", map[string][]byte{"balance": {0, 0, 9, 9}})
	cases := map[string]func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof){
		"account leaf embeds a different storage root": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			// a self-consistent key proof into ANOTHER escrow root, paired with an account leaf rewritten to that root
			s[0] = other.prove("balance")
			a[0].ContractRoot = other.root()
			return s, a
		},
		"key proven in a root the state root does not hold": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			s[0] = other.prove("balance")
			return s, a
		},
		"value": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			s[0].Value[0] ^= 1
			return s, a
		},
		"key": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			s[0].Key = "nonce"
			return s, a
		},
		"key path sibling": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			s[1].KeyPath[0][3] ^= 1
			return s, a
		},
		"key path cut": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			s[1].KeyPath = s[1].KeyPath[:len(s[1].KeyPath)-1]
			return s, a
		},
		"account sibling": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			a[0].Siblings[0][0] ^= 1
			return s, a
		},
		"account index": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			a[0].Index ^= 1
			return s, a
		},
		"account leaf count": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			a[0].Leaves++
			return s, a
		},
		"account contract url": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			a[0].Contract = "acc://app.acme/token"
			return s, a
		},
		"extra sibling": func(s []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			a[0].Siblings = append(a[0].Siblings, [32]byte{})
			return s, a
		},
		"accounts with no key": func(_ []evidence.StorageInclusionProof, a []evidence.AccountInclusionProof) ([]evidence.StorageInclusionProof, []evidence.AccountInclusionProof) {
			return nil, a
		},
	}
	for name, f := range cases {
		s, a := f(clone())
		r := verifyState(t, false, root, func(b *evidence.EvidenceBundle) { b.StorageProofs, b.AccountProofs = s, a })
		if r.ProofLevel == "L2" {
			t.Errorf("%s: still L2", name)
		}
		if name != "key proven in a root the state root does not hold" && (r.Verified || r.ProofLevel != "L0") {
			t.Errorf("%s: verified %v proof %s; want a failure at L0", name, r.Verified, r.ProofLevel)
		}
	}
	// a key proven in an unrelated root with no account inclusion for it still proves the key in THAT root: L1, never L2
	r := verifyState(t, false, root, func(b *evidence.EvidenceBundle) {
		b.StorageProofs = []evidence.StorageInclusionProof{other.prove("balance")}
	})
	if r.ProofLevel != "L1" {
		t.Fatalf("an unbound key proof: proof %s, want L1", r.ProofLevel)
	}
	// premise: the escrow contract's own proof verifies
	sp := escrow.prove("nonce")
	if err := VerifyStorageInclusion(&sp); err != nil {
		t.Fatalf("premise: %v", err)
	}
}

// PV-INT-01: integrity is a precondition of every level. A package whose integrity bindings fail reaches no level and no governance,
// however valid its anchor inclusion, state proofs and approval signatures are.
func TestIntegrityIsAPreconditionOfEveryLevel(t *testing.T) {
	root, storage, account, _ := stateFixture()
	pkg := buildPortableWith(t, true, root, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.StorageProofs, b.AccountProofs = storage, account
	})
	if r := Verify(context.Background(), pkg, Options{}); r.ProofLevel != "L3" || r.GovernanceLevel != "G1" {
		t.Fatalf("premise: the untampered package verifies at %s/%s, want L3/G1", r.ProofLevel, r.GovernanceLevel)
	}
	tampered := *pkg
	tampered.OutcomeDigest = sha256.Sum256([]byte("another outcome"))
	r := Verify(context.Background(), &tampered, Options{})
	if r.ProofLevel != "L0" || r.GovernanceLevel != "ungoverned" || r.Verified {
		t.Fatalf("a package whose outcome digest does not bind: %s/%s verified %v; want L0/ungoverned, not verified", r.ProofLevel, r.GovernanceLevel, r.Verified)
	}
	exportTampered := *pkg
	exportTampered.ExportHash[0] ^= 1
	if r := Verify(context.Background(), &exportTampered, Options{}); r.ProofLevel != "L0" || r.GovernanceLevel != "ungoverned" {
		t.Fatalf("a package whose export hash does not recompute: %s/%s; want L0/ungoverned", r.ProofLevel, r.GovernanceLevel)
	}
}

// FZ-02: the level is monotone in the evidence: removing any one proof never raises a level. FZ-03: the verifier is deterministic.
func TestLevelsAreMonotoneInTheEvidenceAndDeterministic(t *testing.T) {
	root, storage, account, _ := stateFixture()
	rank := map[string]int{"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "ungoverned": 0, "G0": 1, "G1": 2, "G2": 3}
	full := func(b *evidence.EvidenceBundle) { b.StorageProofs, b.AccountProofs = storage, account }
	base := verifyState(t, true, root, full)
	removals := map[string]func(*evidence.EvidenceBundle){
		"anchor inclusion":    func(b *evidence.EvidenceBundle) { full(b); b.AnchorInclusion = nil },
		"account proofs":      func(b *evidence.EvidenceBundle) { full(b); b.AccountProofs = nil },
		"storage proofs":      func(b *evidence.EvidenceBundle) { full(b); b.StorageProofs = nil },
		"all state proofs":    func(b *evidence.EvidenceBundle) { b.AnchorInclusion = nil },
		"approval signature":  func(b *evidence.EvidenceBundle) { full(b); b.ApprovalEvidence[0].Signature = nil },
		"every proof at once": func(b *evidence.EvidenceBundle) { b.AnchorInclusion = nil; b.ApprovalEvidence[0].Signature = nil },
	}
	for name, f := range removals {
		r := verifyState(t, true, root, f)
		if rank[r.ProofLevel] > rank[base.ProofLevel] || rank[r.GovernanceLevel] > rank[base.GovernanceLevel] {
			t.Errorf("removing the %s raised the levels from %s/%s to %s/%s", name, base.ProofLevel, base.GovernanceLevel, r.ProofLevel, r.GovernanceLevel)
		}
	}
	pkg := buildPortableWith(t, true, root, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) { full(b) })
	first := Verify(context.Background(), pkg, Options{})
	for i := 0; i < 5; i++ {
		again := Verify(context.Background(), pkg, Options{})
		if again.ProofLevel != first.ProofLevel || again.GovernanceLevel != first.GovernanceLevel || len(again.Checks) != len(first.Checks) {
			t.Fatalf("run %d differs: %s/%s vs %s/%s", i, again.ProofLevel, again.GovernanceLevel, first.ProofLevel, first.GovernanceLevel)
		}
		for j := range again.Checks {
			if again.Checks[j] != first.Checks[j] {
				t.Fatalf("run %d check %d differs: %+v vs %+v", i, j, again.Checks[j], first.Checks[j])
			}
		}
	}
}
