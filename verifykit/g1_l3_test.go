// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	evidence "github.com/opendlt/infrix-schema/evidence"
)

// brief 28bd rows 1 and 2 (L2992): G1 from approval signatures this verifier checks, L3 from a Merkle inclusion it recomputes.

// The node's approval preimage, byte for byte: infrix-core pkg/workflow/s24_approval_preimage_vector_test.go
// (s24ApprovalPreimageVectorHex), the vector the JS SDK is pinned to as well. The decoder reads the node's bytes, not its own.
const nodeApprovalPreimageVectorHex = "0000001c696e667269782f617070726f76616c2d7369676e61747572652f7632000000066b65726d697400000019696e74656e742d6163633a2f2f616c6963652e61636d652d3100000026696e74656e742d6163633a2f2f616c6963652e61636d652d312d676170342d617070726f7665000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00000000767686f73742d31000000186163633a2f2f616c6963652e61636d652f636f756e7465720000000000000003000000076465706f73697400000008776974686472617700000007c3bc6d6c61757400000000000f4240000000000003d09000000000000000020000000441434d450000000455534443000000000000000a00000000000000140000000b62616c616e6365203e20300000000000000063000000106163633a2f2f616c6963652e61636d650000000561646d696e000000176163633a2f2f616c6963652e61636d652f626f6f6b2f3100000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

func TestApprovalPreimageDecoderReadsTheNodesSharedVector(t *testing.T) {
	raw, err := hex.DecodeString(nodeApprovalPreimageVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeApprovalPreimage(raw)
	if err != nil {
		t.Fatalf("the node's preimage did not decode: %v", err)
	}
	var plan [32]byte
	for i := range plan {
		plan[i] = byte(i)
	}
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(0x40 + i)
	}
	if p.NetworkID != "kermit" || p.WorkflowID != "intent-acc://alice.acme-1" || p.StageID != "intent-acc://alice.acme-1-gap4-approve" ||
		p.PlanHash != plan || p.SignerIdentity != "acc://alice.acme" || p.SignerRole != "admin" || p.KeyPageRef != "acc://alice.acme/book/1" ||
		!bytes.Equal(p.PublicKey, pub) || p.UserSignature {
		t.Fatalf("the node's preimage decoded to the wrong fields: %+v", p)
	}
	// the test-side encoder the fixtures sign with writes the same bytes as the node for the same content
	enc := testApproval{
		NetworkID: "kermit", WorkflowID: "intent-acc://alice.acme-1", StageID: "intent-acc://alice.acme-1-gap4-approve", PlanHash: plan,
		GhostReceiptID: "ghost-1", ContractURL: "acc://alice.acme/counter", Functions: []string{"withdraw", "deposit", "ümlaut"},
		MaxAmount: 1_000_000, MaxGas: 250_000, TargetAssets: []string{"USDC", "ACME"}, MinBlock: 10, MaxBlock: 20, RequiredState: "balance > 0",
		ExpiresAtBlock: 99, Identity: "acc://alice.acme", Role: "admin", KeyPage: "acc://alice.acme/book/1", PublicKey: pub,
	}
	for i := range enc.SimulationHash {
		enc.SimulationHash[i] = byte(0xff - i)
	}
	if got := hex.EncodeToString(enc.preimage()); got != nodeApprovalPreimageVectorHex {
		t.Fatalf("the fixture encoder disagrees with the node's vector:\n got  %s\n want %s", got, nodeApprovalPreimageVectorHex)
	}
	// bites: a byte past the end, a cut, another domain and an unsorted list are each refused
	for name, b := range map[string][]byte{
		"trailing byte":  append(append([]byte(nil), raw...), 0),
		"cut":            raw[:len(raw)-1],
		"another domain": append([]byte{0, 0, 0, 0x1c}, append([]byte("infrix/approval-signature/v1"), raw[32:]...)...),
	} {
		if _, err := decodeApprovalPreimage(b); err == nil {
			t.Errorf("%s: the preimage decoded", name)
		}
	}
	unsorted := enc
	unsorted.Functions = nil
	pre := unsorted.preimage()
	// hand-write an unsorted two-item list in place of the empty one: find the empty list after the contract URL and splice
	idx := bytes.Index(pre, []byte("acc://alice.acme/counter")) + len("acc://alice.acme/counter")
	list := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 'b', 0, 0, 0, 1, 'a'}
	bad := append(append(append([]byte(nil), pre[:idx]...), list...), pre[idx+8:]...)
	if _, err := decodeApprovalPreimage(bad); err == nil {
		t.Error("an unsorted list decoded")
	}
}

func planHashVK() [32]byte { return sha256.Sum256([]byte("vk-plan")) }

func verifyWithApprovals(t *testing.T, anchored bool, approvals ...evidence.ApprovalEvidenceRef) *Report {
	t.Helper()
	pkg := buildPortableWith(t, anchored, [32]byte{7}, "outcome-vk", func(b *evidence.EvidenceBundle) {
		b.ApprovalEvidence = approvals
	}, nil)
	return Verify(context.Background(), pkg, Options{})
}

func checkStatus(r *Report, name string) CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

// A real signature verifies in every scheme the verifier implements, and is NOT enough for G1: G1 also needs the approver key proven on its page
// (approval_key_pages, brief 28bh), which this bundle does not embed, so it stays G0. The positive G1 is TestWithoutAnAccumulateTransactionTheBundleIsExactlyL3G1.
func TestG1IsCreditedFromAVerifiedSignatureInEveryScheme(t *testing.T) {
	for _, scheme := range []string{
		evidence.ApprovalSigTypeInfrixEd25519,
		evidence.ApprovalSigTypeAccumulatePrefix + "ed25519",
		evidence.ApprovalSigTypeAccumulatePrefix + "btc",
		evidence.ApprovalSigTypeAccumulatePrefix + "eth",
	} {
		r := verifyWithApprovals(t, false, signedApproval(t, scheme, planHashVK()))
		if !r.Verified || r.GovernanceLevel != "G0" || checkStatus(r, "approval_signatures") != CheckPass || checkStatus(r, "approval_key_pages") != CheckSkip {
			t.Errorf("%s: verified=%v governance=%s approval_signatures=%s, want a verified signature capped at G0 without a key-page proof (%+v)", scheme, r.Verified, r.GovernanceLevel, checkStatus(r, "approval_signatures"), r.Checks)
		}
	}
	// two approvals, both signed, still G0 without key-page proofs
	r := verifyWithApprovals(t, false, signedApproval(t, evidence.ApprovalSigTypeInfrixEd25519, planHashVK()), signedApproval(t, evidence.ApprovalSigTypeAccumulatePrefix+"btc", planHashVK()))
	if r.GovernanceLevel != "G0" || checkStatus(r, "approval_signatures") != CheckPass {
		t.Fatalf("two signed approvals: governance %s, want G0 with both signatures verified and no key-page proof", r.GovernanceLevel)
	}
}

// A forged approval, an identity string with no signature (what G1 used to be credited from), caps the bundle at G0. The bite
// is the old rule itself: a non-zero plan hash and an identity, which this approval has.
func TestAForgedUnsignedApprovalCapsTheBundleAtG0(t *testing.T) {
	forged := evidence.ApprovalEvidenceRef{StageID: "s1", Identity: "acc://approver.acme", Role: "approver", PlanHash: planHashVK()}
	if !(forged.PlanHash != ([32]byte{}) && forged.Identity != "") {
		t.Fatal("premise: the forged approval does not satisfy the old G1 rule")
	}
	r := verifyWithApprovals(t, false, forged)
	if r.GovernanceLevel != "G0" || checkStatus(r, "approval_signatures") != CheckSkip {
		t.Fatalf("an unsigned approval: governance %s, approval_signatures %s; want G0 and a skip", r.GovernanceLevel, checkStatus(r, "approval_signatures"))
	}
	// one signed approval beside one unsigned: every counted approval must verify, so still G0
	r = verifyWithApprovals(t, false, signedApproval(t, evidence.ApprovalSigTypeInfrixEd25519, planHashVK()), forged)
	if r.GovernanceLevel != "G0" {
		t.Fatalf("a signed and an unsigned approval: governance %s, want G0", r.GovernanceLevel)
	}
	// a scheme the verifier does not implement is not credited either, and is named
	unchecked := signedApproval(t, evidence.ApprovalSigTypeAccumulatePrefix+"ed25519", planHashVK())
	unchecked.SigType = evidence.ApprovalSigTypeAccumulatePrefix + "rcd1"
	r = verifyWithApprovals(t, false, unchecked)
	if r.GovernanceLevel != "G0" || checkStatus(r, "approval_signatures") == CheckPass {
		t.Fatalf("an rcd1 approval: governance %s, want G0", r.GovernanceLevel)
	}
}

// A tampered signature caps the bundle at G0 and fails verification: it is a forgery, not a missing approval. Each binding the
// signature carries is bitten the same way.
func TestATamperedApprovalSignatureOrBindingCapsAtG0AndFails(t *testing.T) {
	other := sha256.Sum256([]byte("another plan"))
	type tamper func(*evidence.ApprovalEvidenceRef)
	cases := map[string]struct {
		scheme string
		f      tamper
	}{
		"signature bit (bare)":   {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.Signature[5] ^= 1 }},
		"signature bit (acc-ed)": {evidence.ApprovalSigTypeAccumulatePrefix + "ed25519", func(a *evidence.ApprovalEvidenceRef) { a.Signature[5] ^= 1 }},
		"signature bit (btc)":    {evidence.ApprovalSigTypeAccumulatePrefix + "btc", func(a *evidence.ApprovalEvidenceRef) { a.Signature[len(a.Signature)-1] ^= 1 }},
		"signature bit (eth)":    {evidence.ApprovalSigTypeAccumulatePrefix + "eth", func(a *evidence.ApprovalEvidenceRef) { a.Signature[40] ^= 1 }},
		"metadata hash":          {evidence.ApprovalSigTypeAccumulatePrefix + "ed25519", func(a *evidence.ApprovalEvidenceRef) { a.SignatureMetadataHash = make([]byte, 32) }},
		"preimage byte":          {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.SignedPreimage[len(a.SignedPreimage)-1] ^= 1 }},
		"stated plan":            {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.PlanHash = other }},
		"stated identity":        {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.Identity = "acc://mallory.acme" }},
		"stated role":            {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.Role = "admin" }},
		"stated stage":           {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.StageID = "s2" }},
		"stated key page":        {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.SignerPage = "acc://mallory.acme/book/1" }},
		"stated key":             {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.PublicKey = bytes.Repeat([]byte{7}, 32) }},
		"declared scheme (bare)": {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) {
			a.SigType = evidence.ApprovalSigTypeAccumulatePrefix + "ed25519"
		}},
		"declared scheme (acc-ed)": {evidence.ApprovalSigTypeAccumulatePrefix + "ed25519", func(a *evidence.ApprovalEvidenceRef) { a.SigType = evidence.ApprovalSigTypeInfrixEd25519 }},
		"signature dropped":        {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.Signature = nil }},
		"key page dropped":         {evidence.ApprovalSigTypeInfrixEd25519, func(a *evidence.ApprovalEvidenceRef) { a.SignerPage = "" }},
		"eth upper-half s": {evidence.ApprovalSigTypeAccumulatePrefix + "eth", func(a *evidence.ApprovalEvidenceRef) {
			var s secp256k1.ModNScalar
			s.SetByteSlice(a.Signature[32:64])
			s.Negate() // n - s verifies as ECDSA but is the malleable twin go-ethereum refuses
			b := s.Bytes()
			copy(a.Signature[32:64], b[:])
		}},
	}
	for name, c := range cases {
		a := signedApproval(t, c.scheme, planHashVK())
		c.f(&a)
		r := verifyWithApprovals(t, false, a)
		want := "G0"
		if name == "stated plan" {
			// the stated plan no longer binds the package's plan hash: integrity fails, so no level at all (PV-INT-01)
			want = "ungoverned"
		}
		if r.GovernanceLevel != want || r.Verified || checkStatus(r, "approval_signatures") != CheckFail {
			t.Errorf("%s: governance %s verified %v approval_signatures %s; want %s, not verified, a fail", name, r.GovernanceLevel, r.Verified, checkStatus(r, "approval_signatures"), want)
		}
	}
	// a real signature over a preimage for ANOTHER plan, stated honestly, is a signature for the wrong plan: refused
	wrongPlan := signedApproval(t, evidence.ApprovalSigTypeInfrixEd25519, other)
	if err := verifyApprovalSignature(wrongPlan, planHashVK()); err == nil {
		t.Fatal("an approval of another plan verified against this package's plan")
	}
}

// --- L3 (row 2) ---

// A node-set "anchored" status with no inclusion proof is not L3, and the status is not what L3 is credited from: a valid
// inclusion credits L3 whatever the status says.
func TestL3IsCreditedFromTheInclusionNotTheAnchorStatus(t *testing.T) {
	// the status says anchored, the anchor record is present, but no inclusion: not anchored, L0
	r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.AnchorInclusion = nil
	}), Options{})
	if r.ProofLevel != "L0" || checkStatus(r, "anchor_proof") != CheckSkip {
		t.Fatalf("anchored status, no inclusion: proof %s anchor_proof %s; want L0 and a skip", r.ProofLevel, checkStatus(r, "anchor_proof"))
	}
	// the status alone, no anchor record and no inclusion (a node that only flips the field): L0
	r = Verify(context.Background(), buildPortableWith(t, false, [32]byte{7}, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.Anchor = evidence.AnchorStatusVerified
	}), Options{})
	if r.ProofLevel != "L0" {
		t.Fatalf("a bare 'verified' status: proof %s, want L0", r.ProofLevel)
	}
	// a valid inclusion: L3
	r = Verify(context.Background(), buildPortable(t, true), Options{})
	if r.ProofLevel != "L3" || checkStatus(r, "anchor_proof") != CheckPass || !r.Verified {
		t.Fatalf("a valid inclusion: proof %s anchor_proof %s verified %v; want a verified L3", r.ProofLevel, checkStatus(r, "anchor_proof"), r.Verified)
	}
	// the same valid inclusion with the status left at "pending": still L3, the status is never read
	r = Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		b.Anchor = evidence.AnchorStatusPending
	}), Options{})
	if r.ProofLevel != "L3" {
		t.Fatalf("a valid inclusion under a 'pending' status: proof %s, want L3", r.ProofLevel)
	}
}

// A tampered inclusion or anchor record fails and is not L3.
func TestL3RefusesATamperedInclusionOrAnchorRecord(t *testing.T) {
	cases := map[string]func(*evidence.EvidenceBundle, *evidence.BuildPortablePackageInputs){
		"path sibling": func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
			b.AnchorInclusion.Path[0][0] ^= 1
		},
		"batch root": func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
			b.AnchorInclusion.BatchRoot[0] ^= 1
		},
		"cut path": func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
			b.AnchorInclusion.Path = b.AnchorInclusion.Path[:1]
		},
		"record bundle hash": func(_ *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) {
			in.AnchorProof.BundleHash[0] ^= 1
		},
		"bundle content after anchoring": func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
			// the content changes after the hash was anchored; the stored BundleHash is left as it was
			b.StateRoot[0] ^= 1
		},
		"record dropped": func(_ *evidence.EvidenceBundle, in *evidence.BuildPortablePackageInputs) {
			in.AnchorProof = nil
			in.AnchorTxHash = ""
			in.AnchorBlock = 0
		},
	}
	for name, f := range cases {
		r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, f), Options{L0Confirmer: okConfirmer()})
		if r.ProofLevel == "L3" || r.ProofLevel == "L4" || r.Verified {
			t.Errorf("%s: proof %s verified %v; want neither L3/L4 nor verified (%+v)", name, r.ProofLevel, r.Verified, r.Checks)
		}
	}
}

// WHAT THE INCLUSION PROVES (brief 28bk row 2, main's condition): the one batch tree hashes sorted pairs, so a path binds membership and
// not the position. An inclusion whose LeafIndex names another real leaf, with a valid path, is judged by what it proves: L3 is credited
// (no false refusal) and the report claims membership, never the index (no false "position verified").
func TestAWrongLeafIndexWithAValidPathIsJudgedByWhatItProves(t *testing.T) {
	r := Verify(context.Background(), buildPortableWith(t, true, [32]byte{7}, "outcome-vk", nil, func(b *evidence.EvidenceBundle, _ *evidence.BuildPortablePackageInputs) {
		if b.AnchorInclusion.LeafCount < 2 {
			t.Fatalf("premise: a multi-leaf batch, got %d leaves", b.AnchorInclusion.LeafCount)
		}
		b.AnchorInclusion.LeafIndex = (b.AnchorInclusion.LeafIndex + 1) % b.AnchorInclusion.LeafCount
	}), Options{})
	detail := ""
	for _, c := range r.Checks {
		if c.Name == "anchor_proof" {
			detail = string(c.Status) + ": " + c.Detail
		}
	}
	if r.ProofLevel != "L3" || !r.Verified || !strings.Contains(detail, "member of the") || !strings.Contains(detail, "not the leaf position") || strings.Contains(detail, "at leaf") {
		t.Fatalf("a valid path under another index: proof %s verified %v, anchor_proof %q; want a verified L3 that claims membership and states the position is not bound", r.ProofLevel, r.Verified, detail)
	}
}

// L4 records its source, and a live query is the only one today.
func TestL4RecordsItsSource(t *testing.T) {
	r := Verify(context.Background(), buildPortable(t, true), Options{L0Confirmer: okConfirmer()})
	if r.ProofLevel != "L4" || r.ProofLevelSource != ProofSourceLiveQuery {
		t.Fatalf("proof %s source %q, want L4 from %s", r.ProofLevel, r.ProofLevelSource, ProofSourceLiveQuery)
	}
	r = Verify(context.Background(), buildPortable(t, true), Options{})
	if r.ProofLevelSource != "" {
		t.Fatalf("an L3 records a source %q", r.ProofLevelSource)
	}
}
