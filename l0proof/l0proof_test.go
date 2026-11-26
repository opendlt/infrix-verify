// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// ---- PV-L4 building blocks ------------------------------------------------------------------------------------------------------------------------

// PV-L4 (offline, embedded-proof): the Kermit capture verifies against the COMPILED Kermit pin with no network access, and the result names that pin.
// Bite: the same chain with its certifying commit's first signature flipped does not verify.
func TestPVL4_KermitChainVerifiesOfflineAgainstTheCompiledPin(t *testing.T) {
	f := loadFixture(t, "kermit")
	r := mustVerify(t, f, f.chain, f.exp, f.opts)
	pin, err := l0proof.CompiledPin(l0proof.NetworkKermit)
	if err != nil {
		t.Fatal(err)
	}
	if r.Network != l0proof.NetworkKermit || r.Pin != pin.ID() || r.PinOverridden {
		t.Fatalf("the verdict does not name the compiled Kermit pin: %+v", r)
	}
	if r.DirectoryHeight != f.chain.Consensus[len(f.chain.Consensus)-1].Header.Height || len(r.TxHash) != 32 || len(r.DirectoryRoot) != 32 {
		t.Fatalf("the verdict does not report the certified height, tx hash and root: %+v", r)
	}
	bite := clone(t, f.chain)
	last := &bite.Consensus[len(bite.Consensus)-1]
	last.Commit.Signatures[0].Signature[0] ^= 1
	mustFail(t, "a Kermit chain with a forged commit signature", bite, f.exp, f.opts, "signature 0 does not verify")
}

// PV-L4 (simulator, labelled): the simulator capture verifies only under its own pin passed EXPLICITLY, and the verdict says so.
// Bite: under the compiled Kermit pin it does not verify.
func TestPVL4_SimulatorChainVerifiesUnderItsExplicitPinOnly(t *testing.T) {
	f := loadFixture(t, "simulator")
	r := mustVerify(t, f, f.chain, f.exp, f.opts)
	if r.Network != "simulator" || !r.PinOverridden {
		t.Fatalf("a simulator verdict must be labelled simulator and overridden: %+v", r)
	}
	mustFail(t, "the simulator chain under the Kermit pin", f.chain, f.exp, l0proof.Options{Network: l0proof.NetworkKermit}, "incarnation")
}

// PV-L4 building block, Accumulate receipts: a path folds as merkle.Receipt.Validate does, and a 33-byte entry is refused (strict validation).
// Bite: flipping one step's side changes the anchor.
func TestPVL4_PathFoldsLikeAnAccumulateReceipt(t *testing.T) {
	a, b, c := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b")), sha256.Sum256([]byte("c"))
	p := l0proof.Path{{Right: true, Hash: b[:]}, {Right: false, Hash: c[:]}}
	got, err := p.Apply(a[:], 8)
	if err != nil {
		t.Fatal(err)
	}
	ab := sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...))
	want := sha256.Sum256(append(append([]byte{}, c[:]...), ab[:]...))
	if !bytes.Equal(got, want[:]) {
		t.Fatal("the path does not fold as combine(sibling-or-self)")
	}
	p[0].Right = false
	if got2, _ := p.Apply(a[:], 8); bytes.Equal(got2, want[:]) {
		t.Fatal("bite: flipping a side did not change the anchor")
	}
	if _, err := (l0proof.Path{{Hash: append(b[:], 0)}}).Apply(a[:], 8); err == nil {
		t.Fatal("a 33-byte entry was accepted")
	}
}

// PV-L4 building block, Accumulate merkle state: MerkleRoot is Hasher.MerkleHash (zero for empty, the element itself for one, peaks folded right to
// left). Bite: reordering two elements changes it.
func TestPVL4_MerkleRootIsTheAccumulateHasher(t *testing.T) {
	h := func(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }
	comb := func(a, b []byte) []byte { x := sha256.Sum256(append(append([]byte{}, a...), b...)); return x[:] }
	if !bytes.Equal(l0proof.MerkleRoot(nil), make([]byte, 32)) {
		t.Fatal("empty list")
	}
	if !bytes.Equal(l0proof.MerkleRoot([][]byte{h("x")}), h("x")) {
		t.Fatal("one element")
	}
	// three elements: peaks (x,y) at height 1 and z at height 0; the anchor folds z first, then combine(peak, z)
	want := comb(comb(h("x"), h("y")), h("z"))
	if !bytes.Equal(l0proof.MerkleRoot([][]byte{h("x"), h("y"), h("z")}), want) {
		t.Fatal("three elements")
	}
	if bytes.Equal(l0proof.MerkleRoot([][]byte{h("y"), h("x"), h("z")}), want) {
		t.Fatal("bite: order did not matter")
	}
}

// ---- BD-01: a proof for something else fails ------------------------------------------------------------------------------------------------------

// BD-01: a valid chain presented for a different value, a different anchor account, or another chain's expectation fails, naming the link.
func TestBD01_AValidChainForADifferentValueFails(t *testing.T) {
	for _, f := range fixtures(t) {
		mustVerify(t, f, f.chain, f.exp, f.opts)
		other := sha256.Sum256(append([]byte("another bundle"), f.exp.Leaf...))
		mustFail(t, f.name+": another value", f.chain, l0proof.Expectation{AnchorAccount: f.exp.AnchorAccount, Leaf: other[:]}, f.opts, "does not carry the expected value")
		mustFail(t, f.name+": another account", f.chain, l0proof.Expectation{AnchorAccount: "acc://someone-else.acme/anchors", Leaf: f.exp.Leaf}, f.opts, "not the anchor account")
	}
	k, s := loadFixture(t, "kermit"), loadFixture(t, "simulator")
	mustFail(t, "the simulator chain for the Kermit expectation", s.chain, k.exp, s.opts, "")
	mustFail(t, "the Kermit chain for the simulator expectation", k.chain, s.exp, k.opts, "")
}

// ---- NL-05 / NL-07: no field a node sets is ever proof ---------------------------------------------------------------------------------------------

// NL-05: a chain whose incarnation differs from the verifier's pin gets no L4. And the incarnation never SELECTS a pin: relabelling the simulator chain
// with the Kermit pin's ID still fails, because its headers are not certified by the Kermit validators.
func TestNL05_AnIncarnationThatIsNotThePinGetsNoL4(t *testing.T) {
	k, s := loadFixture(t, "kermit"), loadFixture(t, "simulator")
	c := clone(t, k.chain)
	c.Incarnation = s.chain.Incarnation
	mustFail(t, "a Kermit chain claiming the simulator incarnation", c, k.exp, k.opts, "not the verifier's pin")
	kpin, _ := l0proof.CompiledPin(l0proof.NetworkKermit)
	c = clone(t, s.chain)
	c.Incarnation = kpin.ID()
	mustFail(t, "a simulator chain relabelled as Kermit", c, s.exp, k.opts, "consensus")
}

// NL-07: a Directory header signed by a validator set not reached from the pin gets no L4, whether it claims to be adjacent to the pin or skips from it.
func TestNL07_AHeaderSignedByASetNotReachedFromThePinGetsNoL4(t *testing.T) {
	s := loadFixture(t, "simulator")
	pin := *s.opts.OverridePin
	last := s.chain.Consensus[len(s.chain.Consensus)-1]
	rogue := keys("nl07-rogue", 4, 10)
	for _, height := range []int64{pin.InitialHeight, last.Header.Height} {
		c := clone(t, s.chain)
		lb := block(pin.ChainID, height, last.Header.Time, last.Header.AppHash, rogue, rogue, nil)
		c.Consensus = []consensus.LightBlock{lb}
		mustFail(t, "a rogue-set header", c, s.exp, s.opts, "unverifiable")
	}
	// the same construction at the consensus level: signed by the pinned set it verifies (the bite), signed by a set the pin never reached it does not
	const chainID = "NL07.Directory"
	v0 := keys("nl07-genesis", 4, 10)
	genesis := consensus.Timestamp{Seconds: 1_700_000_000}
	p := pinOf("nl07", chainID, 1, genesis, v0)
	app := sha256.Sum256([]byte("nl07 root"))
	for _, h := range []int64{1, 7} {
		good := block(chainID, h, consensus.Timestamp{Seconds: genesis.Seconds + h}, app[:], v0, v0, nil)
		if _, err := consensus.VerifyTrace(&p, []consensus.LightBlock{good}, consensus.DefaultLimits); err != nil {
			t.Fatalf("bite: a header signed by the pinned set at height %d does not verify: %v", h, err)
		}
		bad := block(chainID, h, consensus.Timestamp{Seconds: genesis.Seconds + h}, app[:], rogue, rogue, nil)
		if _, err := consensus.VerifyTrace(&p, []consensus.LightBlock{bad}, consensus.DefaultLimits); err == nil {
			t.Fatalf("a header signed by a rogue set at height %d verified", h)
		}
	}
}

// ---- PN-01..03: pins and network events ----------------------------------------------------------------------------------------------------------

// PN-01: Kermit's pin is compiled in; no network, an unknown network or mainnet has no pin; an override is used only when passed explicitly and the
// verdict says so; a returned pin is a copy the caller cannot alter.
func TestPN01_TheKermitPinIsCompiledInAndAnOverrideIsOnlyExplicit(t *testing.T) {
	k := loadFixture(t, "kermit")
	for _, n := range []string{"", "mainnet", "simulator"} {
		mustFail(t, "network "+n, k.chain, k.exp, l0proof.Options{Network: n}, "pin")
	}
	pin, err := l0proof.CompiledPin(l0proof.NetworkKermit)
	if err != nil || pin.Network != l0proof.NetworkKermit || pin.ChainID != "DevNet.Directory" || pin.InitialHeight != 2 || len(pin.Validators.Validators) != 3 {
		t.Fatalf("the compiled Kermit pin is not the 2026-02-01 Directory genesis: %+v %v", pin, err)
	}
	pin.Validators.Validators[0].PubKey[0] ^= 1
	again, _ := l0proof.CompiledPin(l0proof.NetworkKermit)
	if bytes.Equal(again.Validators.Validators[0].PubKey, pin.Validators.Validators[0].PubKey) {
		t.Fatal("altering a returned pin altered the compiled pin")
	}
	r := mustVerify(t, k, k.chain, k.exp, l0proof.Options{Network: "ignored-when-overridden", OverridePin: &again})
	if !r.PinOverridden {
		t.Fatal("an explicit override is not reported")
	}
	// bite: an override that is not the incarnation fails
	mustFail(t, "a wrong override", k.chain, k.exp, l0proof.Options{OverridePin: &pin}, "not the verifier's pin")
}

// PN-02: after a reset (a new incarnation), an old proof verifies only against the old pin, passed explicitly, and the verdict names the pin used.
func TestPN02_AResetMakesOldProofsVerifyOnlyAgainstTheOldPin(t *testing.T) {
	s := loadFixture(t, "simulator")
	old := *s.opts.OverridePin
	reset := old
	reset.GenesisTime.Seconds += 86400
	reset.Validators = consensus.ValidatorSet{Validators: append([]consensus.Validator(nil), old.Validators.Validators...)}
	if reset.ID() == old.ID() {
		t.Fatal("a new genesis must be a new incarnation")
	}
	mustFail(t, "an old proof against the new incarnation", s.chain, s.exp, l0proof.Options{OverridePin: &reset}, "not the verifier's pin")
	r := mustVerify(t, s, s.chain, s.exp, l0proof.Options{OverridePin: &old})
	if r.Pin != old.ID() {
		t.Fatalf("the verdict names %s, not the old pin %s", r.Pin, old.ID())
	}
	if len(l0proof.PreviousPins(l0proof.NetworkKermit)) != 0 {
		t.Fatal("no earlier Kermit incarnation is recorded")
	}
}

// PN-03: validator-set changes after genesis are verified one step at a time. A complete rotation needs its transition: without it the new set cannot be
// trusted; with a forged transition the verdict names the step; nothing is ever partially credited.
func TestPN03_TransitionsAreVerifiedStepByStep(t *testing.T) {
	const chainID = "PN03.Directory"
	v0, v1 := keys("pn03-genesis", 4, 10), keys("pn03-rotated", 4, 10)
	genesis := consensus.Timestamp{Seconds: 1_700_000_000}
	pin := pinOf("pn03", chainID, 1, genesis, v0)
	app := sha256.Sum256([]byte("pn03 root"))
	at := func(h int64) consensus.Timestamp { return consensus.Timestamp{Seconds: genesis.Seconds + h} }
	transition := block(chainID, 5, at(5), app[:], v0, v1, nil) // signed by the genesis set, names the rotated set next
	target := block(chainID, 9, at(9), app[:], v1, v1, nil)     // signed only by the rotated set
	if _, err := consensus.VerifyTrace(&pin, []consensus.LightBlock{transition, target}, consensus.DefaultLimits); err != nil {
		t.Fatalf("the full trace must verify: %v", err)
	}
	// without the transition, a disjoint set cannot be trusted from the pin
	_, err := consensus.VerifyTrace(&pin, []consensus.LightBlock{target}, consensus.DefaultLimits)
	var se *consensus.StepError
	if !errors.As(err, &se) || se.Step != 0 || !strings.Contains(err.Error(), "cannot be trusted") {
		t.Fatalf("a skipped rotation was not refused by name: %v", err)
	}
	// a forged transition is named, and the target after it is not credited
	forged := transition
	forged.Commit.Signatures = append([]consensus.CommitSig(nil), transition.Commit.Signatures...)
	forged.Commit.Signatures[2].Signature = append([]byte(nil), forged.Commit.Signatures[2].Signature...)
	forged.Commit.Signatures[2].Signature[5] ^= 0x40
	last, err := consensus.VerifyTrace(&pin, []consensus.LightBlock{forged, target}, consensus.DefaultLimits)
	if last != nil || !errors.As(err, &se) || se.Step != 0 || se.Height != 5 {
		t.Fatalf("a forged transition was not named or something was credited: %v %v", last, err)
	}
	// through the chain verifier, an unverifiable transition is "no L4" with the step named
	s := loadFixture(t, "simulator")
	c := clone(t, s.chain)
	c.Consensus[1].Commit.Signatures[0].Signature[0] ^= 1
	mustFail(t, "a simulator chain with a forged middle step", c, s.exp, s.opts, "consensus step 1")
}

// ---- PF-01: bounds -------------------------------------------------------------------------------------------------------------------------------

// PF-01: the largest captured chain verifies within a declared time and memory bound, and every oversized proof is refused by name, never truncated.
func TestPF01_ProofsAreBoundedAndOversizedOnesAreRefusedByName(t *testing.T) {
	const timeBound = 250 * time.Millisecond
	const memBound = 8 << 20
	var largest *fixture
	for _, f := range fixtures(t) {
		if largest == nil || len(f.raw) > len(largest.raw) {
			largest = f
		}
	}
	const n = 20
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	start := time.Now()
	for i := 0; i < n; i++ {
		c, err := l0proof.Decode(largest.raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		mustVerify(t, largest, c, largest.exp, largest.opts)
	}
	per := time.Since(start) / n
	runtime.ReadMemStats(&ms1)
	alloc := (ms1.TotalAlloc - ms0.TotalAlloc) / n
	t.Logf("the %s chain (%d bytes) decodes and verifies in %v and %d bytes", largest.name, len(largest.raw), per, alloc)
	if per > timeBound || alloc > memBound {
		t.Fatalf("verification took %v and %d bytes; the declared bound is %v and %d bytes", per, alloc, timeBound, memBound)
	}

	lim := l0proof.DefaultLimits
	small := lim
	small.MaxProofBytes = len(largest.raw) - 1
	if _, err := l0proof.Decode(largest.raw, &small); !errors.Is(err, l0proof.ErrProofTooLarge) {
		t.Fatalf("an oversized encoding was not refused by name: %v", err)
	}
	k := loadFixture(t, "kermit")
	over := func(mut func(l *l0proof.Limits), reason string) {
		t.Helper()
		l := lim
		mut(&l)
		mustFail(t, "over a limit: "+reason, k.chain, k.exp, l0proof.Options{Network: l0proof.NetworkKermit, Limits: &l}, reason)
	}
	over(func(l *l0proof.Limits) { l.MaxPathSteps = 1 }, "over the limit of 1")
	over(func(l *l0proof.Limits) { l.MaxEntryItems = 0 }, "items, over the limit")
	over(func(l *l0proof.Limits) { l.MaxTransactionBytes = 70 }, "over the limit of 70")
	over(func(l *l0proof.Limits) { l.MaxMainStateBytes = 10 }, "main state is")
	over(func(l *l0proof.Limits) { l.MaxChains = 1 }, "chains; between 1 and 1")
	over(func(l *l0proof.Limits) { l.Consensus.MaxValidators = 2 }, "over the limit of 2")
	over(func(l *l0proof.Limits) { l.Consensus.MaxSteps = 0 }, "steps, over the limit of 0")
	// bite: at the defaults the same chain verifies
	mustVerify(t, k, k.chain, k.exp, l0proof.Options{Network: l0proof.NetworkKermit, Limits: &lim})
}
