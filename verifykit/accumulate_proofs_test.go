// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// THE ACCUMULATE-PROVEN BUNDLE FIXTURE (testdata/accumulate, SIMULATOR-labelled; brief 28bh).
//
// It is made in two steps, because a bundle's hash is not reproducible (its evidence chain stamps times) and the L0 proofs must prove THAT bundle:
//
//  1. VERIFYKIT_WRITE_ACC_TARGET=1 go test -run TestAccumulateFixtureTarget ./verifykit/ writes bundle.json (a governed, anchored bundle whose two approvals
//     are accumulate-ed25519 signatures by keys of a 2-of-3 page) and target.json (its batch root, plan hash, bundle id, the page's key seeds).
//  2. cd l0proofref && GOVPROOF_WRITE_FIXTURES=1 go test -run TestAccumulateBundleProofs . runs the in-process Accumulate simulator with that page, writes
//     the batch root as the single data item of a WriteData, executes the M-of-N approval WriteData, captures the page AT EXECUTION TIME, and writes
//     proofs.json (the l0Proof, keyPageProofs and governanceExecution, and the simulator pin).
//
// Every test here verifies with that pin passed EXPLICITLY (Options.L0Pin): a simulator proof is never a Kermit claim.

var accDir = filepath.Join("testdata", "accumulate")

const (
	accApp     = "acc://infrix-vk.acme"
	accPage    = accApp + "/book/1"
	accAccount = accApp + "/governance"
)

// accSeeds are the seeds of the governance page's three keys; the first two approve.
var accSeeds = [][]byte{bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x32}, 32), bytes.Repeat([]byte{0x33}, 32)}

type accTarget struct {
	BatchRoot hexBytes   `json:"batchRoot"`
	PlanHash  hexBytes   `json:"planHash"`
	BundleID  string     `json:"bundleId"`
	Page      string     `json:"page"`
	Account   string     `json:"account"`
	Seeds     []hexBytes `json:"seeds"`
}

type accProofs struct {
	L0Proof             json.RawMessage   `json:"l0Proof"`
	KeyPageProofs       []json.RawMessage `json:"keyPageProofs"`
	GovernanceExecution json.RawMessage   `json:"governanceExecution"`
	Pin                 consensus.Pin     `json:"pin"`
}

type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }
func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

// accApproval is an accumulate-ed25519 approval of planHash by page key i, signed against page version 1.
func accApproval(t *testing.T, i int, planHash [32]byte) evidence.ApprovalEvidenceRef {
	return accApprovalBy(t, accSeeds[i], 1, uint64(i), planHash)
}

// accApprovalBy is an accumulate-ed25519 approval by the key from seed, signed against page version.
func accApprovalBy(t *testing.T, seed []byte, version, n uint64, planHash [32]byte) evidence.ApprovalEvidenceRef {
	k := ed25519.NewKeyFromSeed(seed)
	a := testApproval{
		NetworkID: "simulator", WorkflowID: "intent-vk", StageID: "s1", PlanHash: planHash,
		ContractURL: accApp + "/escrow", Functions: []string{"release"}, MaxGas: 250_000,
		Identity: accApp, Role: "approver", KeyPage: accPage, PublicKey: k.Public().(ed25519.PublicKey),
		SignatureType: "ed25519", SignerVersion: version, Timestamp: 1_700_000_000_000_000 + n,
	}
	ref := evidence.ApprovalEvidenceRef{StageID: a.StageID, Identity: a.Identity, Role: a.Role, PlanHash: planHash,
		SigType: evidence.ApprovalSigTypeAccumulatePrefix + "ed25519", SignerPage: accPage, PublicKey: a.PublicKey}
	ref.SignedPreimage = a.preimage()
	h := sha256.Sum256(ref.SignedPreimage)
	d := sha256.Sum256(append(append([]byte(nil), testMetadataHash[:]...), h[:]...))
	ref.Signature = ed25519.Sign(k, d[:])
	ref.SignatureMetadataHash = testMetadataHash[:]
	return ref
}

// TestAccumulateFixtureTarget writes step 1 of the fixture when asked; otherwise it holds the committed bundle and target to each other.
func TestAccumulateFixtureTarget(t *testing.T) {
	if os.Getenv("VERIFYKIT_WRITE_ACC_TARGET") == "1" {
		planHash := planHashVK()
		var bundle *evidence.EvidenceBundle
		buildPortableWith(t, true, [32]byte{7}, "outcome-vk", func(b *evidence.EvidenceBundle) {
			b.ApprovalEvidence = []evidence.ApprovalEvidenceRef{accApproval(t, 0, planHash), accApproval(t, 1, planHash)}
			b.ExternalProofs = nil
		}, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) { bundle = b })
		data, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		tg := accTarget{BatchRoot: bundle.AnchorInclusion.BatchRoot[:], PlanHash: planHash[:], BundleID: bundle.ID, Page: accPage, Account: accAccount}
		for _, s := range accSeeds {
			tg.Seeds = append(tg.Seeds, s)
		}
		tdata, err := json.MarshalIndent(tg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(accDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range map[string][]byte{"bundle.json": data, "target.json": tdata} {
			if err := os.WriteFile(filepath.Join(accDir, name), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, tg := loadAccBundle(t), loadAccTarget(t)
	if !bytes.Equal(b.AnchorInclusion.BatchRoot[:], tg.BatchRoot) || b.ID != tg.BundleID {
		t.Fatal("the committed bundle and target disagree")
	}
}

func loadAccBundle(t *testing.T) *evidence.EvidenceBundle {
	data, err := os.ReadFile(filepath.Join(accDir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b evidence.EvidenceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func loadAccTarget(t *testing.T) *accTarget {
	data, err := os.ReadFile(filepath.Join(accDir, "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tg accTarget
	if err := json.Unmarshal(data, &tg); err != nil {
		t.Fatal(err)
	}
	return &tg
}

func loadAccProofs(t *testing.T) *accProofs {
	data, err := os.ReadFile(filepath.Join(accDir, "proofs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p accProofs
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// accPackage builds the portable package of the committed bundle with the embedded proofs mutate leaves in place.
func accPackage(t *testing.T, mutate func(b *evidence.EvidenceBundle, p *accProofs)) *evidence.PortableEvidencePackage {
	t.Helper()
	b, p := loadAccBundle(t), loadAccProofs(t)
	b.L0Proof, b.KeyPageProofs, b.GovernanceExecution = p.L0Proof, p.KeyPageProofs, p.GovernanceExecution
	if mutate != nil {
		mutate(b, p)
	}
	data, err := evidence.CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	var incl []evidence.MerkleInclusionProof
	for i := range b.Chain.Links {
		if proof, perr := evidence.GenerateMerkleInclusionProof(b, i); perr == nil && proof != nil {
			incl = append(incl, *proof)
		}
	}
	in := evidence.BuildPortablePackageInputs{
		BundleData: data, PlanHash: planHashVK(), OutcomeDigest: sha256.Sum256([]byte("vk-outcome-canonical")), InclusionProofs: incl,
		PolicyDecisions: b.PolicyDecisions,
		AnchorProof: &evidence.EvidenceAnchorData{Version: 2, BundleID: b.ID, BundleHash: b.BundleHash, ChainHash: b.Chain.ChainHash, StateRoot: b.StateRoot,
			Level: string(b.Level), BlockHeight: b.AnchorBlock},
		AnchorTxHash: b.AnchorTxHash, AnchorBlock: b.AnchorBlock,
	}
	pkg, err := evidence.BuildPortablePackageWithBindings(in)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func accOpts(t *testing.T) Options {
	p := loadAccProofs(t)
	return Options{L0Pin: &p.Pin, GovernanceAccount: accAccount, GovernancePage: accPage}
}

func detail(r *Report, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return string(c.Status) + ": " + c.Detail
		}
	}
	return ""
}

// PV-L4-01 (simulator twin) + PV-G1-02 + PV-G2-01 at the bundle level: the embedded chain reaches L4 offline with source embedded-proof, the approver keys
// are proven on their page (G1), and the Accumulate-executed approval reaches G2.
func TestAccumulateProvenBundleReachesL4G2Offline(t *testing.T) {
	r := Verify(context.Background(), accPackage(t, nil), accOpts(t))
	if !r.Verified || r.ProofLevel != "L4" || r.GovernanceLevel != "G2" || r.ProofLevelSource != ProofSourceEmbeddedProof || r.GovernanceBinding != GovernanceBindingExecuted {
		t.Fatalf("verified=%v %s/%s source=%q: %+v", r.Verified, r.ProofLevel, r.GovernanceLevel, r.ProofLevelSource, r.Checks)
	}
	for _, c := range []string{"embedded_l0_proof", "approval_key_pages", "governance_execution"} {
		if checkStatus(r, c) != CheckPass {
			t.Fatalf("%s: %s", c, detail(r, c))
		}
	}
}

// RT-02 shape: with no Accumulate transaction (no embedded chain, no governance execution) the same bundle is exactly L3/G1, and nothing claims more.
func TestWithoutAnAccumulateTransactionTheBundleIsExactlyL3G1(t *testing.T) {
	r := Verify(context.Background(), accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) {
		b.L0Proof, b.GovernanceExecution = nil, nil
	}), accOpts(t))
	if !r.Verified || r.ProofLevel != "L3" || r.GovernanceLevel != "G1" || r.ProofLevelSource != "" || r.GovernanceBinding != GovernanceBindingVersion {
		t.Fatalf("verified=%v %s/%s source=%q: %+v", r.Verified, r.ProofLevel, r.GovernanceLevel, r.ProofLevelSource, r.Checks)
	}
}

// G1 needs the key-page proof: with none, a verified signature alone is G0.
func TestASignatureWithoutAKeyPageProofIsG0(t *testing.T) {
	r := Verify(context.Background(), accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) {
		b.KeyPageProofs, b.GovernanceExecution = nil, nil
	}), accOpts(t))
	if r.GovernanceLevel != "G0" || checkStatus(r, "approval_signatures") != CheckPass || checkStatus(r, "approval_key_pages") != CheckSkip {
		t.Fatalf("%s: %+v", r.GovernanceLevel, r.Checks)
	}
	// one approval of a 2-of-3 page is below the PROVEN threshold (a bundle the node SEALED with one approval: its hash is its own, so it is
	// not the anchored leaf, and the one approval is judged against the proven page)
	r = Verify(context.Background(), accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) {
		b.ApprovalEvidence = b.ApprovalEvidence[:1]
		b.GovernanceExecution = nil
		b.BundleHash = mustBundleHash(t, b)
	}), accOpts(t))
	if r.GovernanceLevel != "G0" || !strings.Contains(detail(r, "approval_key_pages"), "requires 2") {
		t.Fatalf("one of two approvals: %s %s", r.GovernanceLevel, detail(r, "approval_key_pages"))
	}
}

// NL-06: a node-asserted success (a recorded "success" outcome, a self-asserted verified external proof) with no Accumulate receipt never reaches G2.
func TestNL06_ANodeAssertedSuccessWithNoReceiptIsNotG2(t *testing.T) {
	r := Verify(context.Background(), accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) {
		b.GovernanceExecution = nil
		b.StepOutcomes = []evidence.StepOutcomeRef{{StageID: "approve", Status: "success"}}
	}), accOpts(t))
	if r.GovernanceLevel == "G2" {
		t.Fatalf("a node-asserted success with no receipt reached G2: %+v", r.Checks)
	}
	// and with the receipt present but no relying-party governance page, G2 is not credited from the bundle's own say-so
	o := accOpts(t)
	o.GovernancePage, o.GovernanceAccount = "", ""
	if r := Verify(context.Background(), accPackage(t, nil), o); r.GovernanceLevel == "G2" {
		t.Fatalf("G2 was credited with no relying-party governance page: %+v", r.Checks)
	}
}

// BD-03 at the bundle level: the governance execution of THIS plan for THIS bundle, never one for another bundle.
func TestBD03_TheGovernanceExecutionOfAnotherBundleFails(t *testing.T) {
	r := Verify(context.Background(), accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) { b.ID = "bundle-other" }), accOpts(t))
	if r.GovernanceLevel == "G2" || checkStatus(r, "governance_execution") == CheckPass {
		t.Fatalf("another bundle's governance execution was credited: %s", detail(r, "governance_execution"))
	}
}

// PN-01: the embedded proofs verify only against the pin the RELYING PARTY chose. With no pin passed the verifier holds only the compiled Kermit pin,
// so a simulator chain cannot be judged at all: nothing embedded is credited (the verdict is L3/G0 from the verifier's own recomputation), and every
// embedded check names the pin the relying party must pass (brief 28bl row 1). With an explicit pin of another network, the chain is refused.
func TestTheEmbeddedProofsUseTheVerifiersPinNeverTheBundles(t *testing.T) {
	o := accOpts(t)
	o.L0Pin = nil
	r := Verify(context.Background(), accPackage(t, nil), o)
	if r.ProofLevel != "L3" || r.GovernanceLevel != "G0" || !r.Verified {
		t.Fatalf("with no pin passed: verified %v %s/%s, want a verified L3/G0 (nothing embedded credited): %+v", r.Verified, r.ProofLevel, r.GovernanceLevel, r.Checks)
	}
	for _, c := range []string{"embedded_l0_proof", "approval_key_pages", "governance_execution"} {
		if d := detail(r, c); !strings.HasPrefix(d, string(CheckSkip)+":") || !strings.Contains(d, "which this verifier does not hold") || !strings.Contains(d, PinFlagHint) {
			t.Fatalf("%s does not name the pin to pass: %s", c, d)
		}
	}
	other := loadAccProofs(t).Pin
	other.ChainID += "-other"
	o.L0Pin = &other
	r = Verify(context.Background(), accPackage(t, nil), o)
	if r.ProofLevel == "L4" || r.GovernanceLevel == "G1" || r.GovernanceLevel == "G2" || r.Verified {
		t.Fatalf("a chain was credited (or passed) under another explicit pin: verified %v %s/%s", r.Verified, r.ProofLevel, r.GovernanceLevel)
	}
	if d := detail(r, "embedded_l0_proof"); !strings.HasPrefix(d, string(CheckFail)+":") || !strings.Contains(d, "not the verifier's pin") {
		t.Fatalf("embedded_l0_proof under another explicit pin: %s", d)
	}
}

// G2 with a referenced credential: G2 needs the referenced credential independently confirmed; the self-asserted Verified flag is never read. (A bundle's
// external proofs are in its BundleHash, so the rule is held on the level function, with every other G2 condition met.)
func TestG2NeedsTheReferencedCredentialConfirmed(t *testing.T) {
	b := &evidence.EvidenceBundle{PolicyDecisions: []evidence.DecisionProofRef{{Decision: "allow"}},
		ExternalProofs: []evidence.ExternalProofRef{{SourceChain: "acc", ProofType: "vc", Verified: true}}}
	if g := computeGovernanceLevel(b, true, true, true, true, false, true); g.String() != "G1" {
		t.Fatalf("an unconfirmed credential reached %s", g)
	}
	if g := computeGovernanceLevel(b, true, true, true, true, true, true); g.String() != "G2" {
		t.Fatalf("a confirmed credential with every other G2 condition: %s", g)
	}
	if g := computeGovernanceLevel(b, true, true, true, false, true, true); g.String() != "G1" {
		t.Fatalf("a confirmed credential without an Accumulate-executed approval reached %s", g)
	}
	if g := computeGovernanceLevel(b, true, true, true, true, true, false); g.String() != "G1" {
		t.Fatalf("an unanchored bundle reached %s", g)
	}
}

// The key-page check, held on its own (an approval is part of BundleHash, so these cases change the approvals in place and call the check directly): an
// approval signed against another page version, by a key not on the page, or naming a page no proof proves is not credited; a proof of a page no
// approval names is refused.
func TestApprovalKeyPagesRefuseEveryMismatch(t *testing.T) {
	o := accOpts(t)
	p := loadAccProofs(t)
	run := func(mutate func(b *evidence.EvidenceBundle)) (bool, string) {
		b := loadAccBundle(t)
		b.KeyPageProofs = p.KeyPageProofs
		mutate(b)
		r := &Report{}
		ok := r.checkApprovalKeyPages(b, true, o)
		return ok, detail(r, "approval_key_pages")
	}
	if ok, d := run(func(*evidence.EvidenceBundle) {}); !ok {
		t.Fatalf("premise: the committed approvals are proven: %s", d)
	}
	cases := map[string]struct {
		mutate func(b *evidence.EvidenceBundle)
		want   string
	}{
		"page version + 1": {func(b *evidence.EvidenceBundle) {
			b.ApprovalEvidence[1] = accApprovalBy(t, accSeeds[1], 2, 1, planHashVK())
		}, "signed against version 2"},
		"page version - 1": {func(b *evidence.EvidenceBundle) {
			b.ApprovalEvidence[1] = accApprovalBy(t, accSeeds[1], 0, 1, planHashVK())
		}, "signed against version 0"},
		"a key not on the page": {func(b *evidence.EvidenceBundle) {
			b.ApprovalEvidence[1] = accApprovalBy(t, bytes.Repeat([]byte{0x77}, 32), 1, 1, planHashVK())
		}, "is not on the proven page"},
		"a repeated approver": {func(b *evidence.EvidenceBundle) { b.ApprovalEvidence[1] = b.ApprovalEvidence[0] }, "requires 2"},
		"an unproven page":    {func(b *evidence.EvidenceBundle) { b.KeyPageProofs = nil }, "embeds no key-page proofs"},
		"a bare signature": {func(b *evidence.EvidenceBundle) {
			b.ApprovalEvidence[1] = signedApproval(t, evidence.ApprovalSigTypeInfrixEd25519, planHashVK())
			b.ApprovalEvidence[1].SignerPage = accPage
		}, ""},
		"a page twice": {func(b *evidence.EvidenceBundle) { b.KeyPageProofs = append(b.KeyPageProofs, b.KeyPageProofs[0]) }, "repeats page"},
	}
	for name, c := range cases {
		ok, d := run(c.mutate)
		if ok || !strings.Contains(d, c.want) {
			t.Errorf("%s: credited=%v detail %q, want a refusal naming %q", name, ok, d, c.want)
		}
	}
}

// brief 28bl row 1: the report names the pin its embedded-proof levels rest on (network, ID, supplied by the relying party), so a surface can say
// whose network an L4/G2 is relative to; with nothing credited from an embedded proof there is no trust root to name.
func TestTheReportNamesTheTrustRootOfItsEmbeddedLevels(t *testing.T) {
	o := accOpts(t)
	r := Verify(context.Background(), accPackage(t, nil), o)
	if r.LevelSources["L4"] != LevelSourceEmbeddedProof || r.EmbeddedTrustRoot == nil {
		t.Fatalf("an embedded L4 names no trust root: %v %+v", r.LevelSources, r.EmbeddedTrustRoot)
	}
	if tr := r.EmbeddedTrustRoot; tr.Network != o.L0Pin.Network || tr.Pin != o.L0Pin.ID() || !tr.Supplied {
		t.Fatalf("the trust root is %+v, want the relying party's pin %s %s", tr, o.L0Pin.Network, o.L0Pin.ID())
	}
	o.L0Pin = nil
	if r := Verify(context.Background(), accPackage(t, nil), o); r.EmbeddedTrustRoot != nil {
		t.Fatalf("nothing embedded was credited, yet the report names a trust root: %+v", r.EmbeddedTrustRoot)
	}
}

// mustBundleHash is the hash a node that sealed b as it now stands would have stamped on it.
func mustBundleHash(t *testing.T, b *evidence.EvidenceBundle) [32]byte {
	t.Helper()
	h, err := b.ComputeBundleHash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}
