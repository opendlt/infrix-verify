// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package govproof is Infrix's own verifier of Accumulate-proven governance (the native proof plan, phase 5): that a key held a place on a key page at a
// block the Directory certified (KeyPageProof), and that Accumulate itself executed an M-of-N approval of a plan under an app's governance page
// (GovernanceExecution). It builds on l0proof's building blocks (the BPT account proof, the receipt path, the consensus trace from a PINNED genesis) and,
// like l0proof, depends on the standard library and crypto only. NO certen code.
//
// A key-page proof is a chain of links, each computed by the verifier from the content below it:
//
//	page state     -- Page.StatePath --------> the partition BPT root        the page's BPT value recomputed from its state (l0proof.AccountProof.State)
//	ledger state   -- Ledger.StatePath ------> the SAME partition BPT root   the partition's system ledger (acc://<partition>.acme/ledger): its main state
//	                                                                          names the block (Index), and its root-chain anchor binds the block to a
//	                                                                          transaction's entry path (below)
//	BPT root       -- Directory.AnchorPath --> the Directory root anchor     the partition anchored its BPT root on the Directory (an element of
//	                                                                          acc://dn.acme/anchors' anchor(<partition>)-bpt chain), then the Directory
//	                                                                          root chain, exactly as l0proof's root-anchor hop
//	Directory root -- Directory.Ledger ------> the Directory BPT root == the AppHash of a header certified by consensus.VerifyTrace from the pin.
//
// A partition anchors its BPT root only for a block that carried messages (crosschain.ConstructLastAnchor), and Kermit serves no historical BPT proofs, so
// the node captures a key-page proof AT EXECUTION TIME: in the window right after the governed block that used the page.
package govproof

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// KeyPageProof proves a key page's state at a partition block certified by the Directory.
type KeyPageProof struct {
	// Incarnation is the ID of the pin the proof was captured under. A LABEL: the verifier compares it with its own pin and refuses a mismatch.
	Incarnation string `json:"incarnation"`
	// Page and Height are LABELS: the page URL and the block the proof is for. The verifier refuses a proof whose proven page or block differs.
	Page   string `json:"page"`
	Height uint64 `json:"height"`
	// Partition is a LABEL of the directory-root form (directoryroot.go): the partition whose anchor certifies the page's BPT root. The verifier
	// refuses a proof whose anchor names another partition. Empty in the ledger form.
	Partition string `json:"partition,omitempty"`
	// PageState is the key page's state in the partition BPT; LedgerState the partition's system ledger in the same BPT. LedgerState.Chain names the
	// ledger's root chain. The directory-root form carries no ledger (LedgerState empty and omitted) and carries PartitionAnchor instead.
	PageState       l0proof.AccountProof `json:"pageState"`
	LedgerState     l0proof.AccountProof `json:"ledgerState,omitzero"`
	PartitionAnchor *PartitionAnchor     `json:"partitionAnchor,omitempty"`
	// Directory carries the partition BPT root into the Directory BPT root.
	Directory l0proof.DirectoryHop `json:"directory"`
	// Consensus is the trace of Directory light blocks from the pin; the last certifies the Directory root as its AppHash.
	Consensus []consensus.LightBlock `json:"consensus"`
}

// ledgerRootChain is the index of the root chain among a system ledger's chains.
const ledgerRootChain = 3

// KeyPage is what a verified key-page proof establishes.
type KeyPage struct {
	URL             string
	AcceptThreshold uint64
	Version         uint64
	KeyHashes       [][]byte
}

// Has reports whether the page lists the key hash.
func (p *KeyPage) Has(keyHash []byte) bool {
	for _, h := range p.KeyHashes {
		if bytes.Equal(h, keyHash) {
			return true
		}
	}
	return false
}

// KeyPageResult is the verdict on a key-page proof. Verified is true only when every link was checked; otherwise Reason names the first that failed.
type KeyPageResult struct {
	Verified      bool
	Reason        string
	Pin           string
	PinOverridden bool
	// Form is FormLedger or FormDirectoryRoot.
	Form            string
	Page            KeyPage
	Partition       string // the partition's system ledger URL
	Height          uint64 // the partition block, read from the proven ledger (or, in the directory-root form, from the partition's anchor)
	BlockTime       int64  // the partition block's time (Unix seconds), read from the proven ledger; 0 and named in Unproven when not proven
	RootAnchor      []byte // the partition's root-chain anchor at that block, read from the proven ledger (or, in the directory-root form, from the partition anchor)
	DirectoryHeight int64
	// HeightProvenBy names what proves Height in the directory-root form (HeightByPartitionAnchor); empty in the ledger form, where the proven
	// ledger states it.
	HeightProvenBy string
	// Unproven names what the proof does not establish and the verifier therefore does not claim (UnprovenBlockTime in the directory-root form).
	Unproven []string
}

func failKP(r KeyPageResult, format string, args ...any) KeyPageResult {
	return KeyPageResult{Reason: fmt.Sprintf(format, args...), Pin: r.Pin, PinOverridden: r.PinOverridden}
}

// selectPin mirrors l0proof's rule: the relying party's explicit override when given, otherwise the pin compiled in for the network. Never the proof's.
func selectPin(opts l0proof.Options) (*consensus.Pin, bool, error) {
	if opts.OverridePin != nil {
		p := *opts.OverridePin
		p.Validators.Validators = append([]consensus.Validator(nil), opts.OverridePin.Validators.Validators...)
		return &p, true, nil
	}
	p, err := l0proof.CompiledPin(opts.Network)
	if err != nil {
		return nil, false, err
	}
	return &p, false, nil
}

func limits(opts l0proof.Options) *l0proof.Limits {
	if opts.Limits != nil {
		return opts.Limits
	}
	return &l0proof.DefaultLimits
}

// VerifyKeyPage checks every link of a key-page proof against the verifier's pin. It never panics and never credits a partial proof.
func VerifyKeyPage(p *KeyPageProof, opts l0proof.Options) KeyPageResult {
	var res KeyPageResult
	pin, overridden, err := selectPin(opts)
	if err != nil {
		return failKP(res, "%v", err)
	}
	res.Pin, res.PinOverridden = pin.ID(), overridden
	if p == nil {
		return failKP(res, "no key-page proof")
	}
	if p.Incarnation != res.Pin {
		return failKP(res, "the key-page proof was captured under incarnation %q, not the verifier's pin %q (%s)", p.Incarnation, res.Pin, pin.Network)
	}
	lim := limits(opts)

	// the page and the ledger are in one partition BPT
	ps, err := p.PageState.State(lim)
	if err != nil {
		return failKP(res, "page state: %v", err)
	}
	page, err := l0proof.DecodeKeyPage(p.PageState.MainState)
	if err != nil {
		return failKP(res, "page state: %v", err)
	}
	var keyHashes [][]byte
	for _, k := range page.Keys {
		// a delegate-only entry is not a key of this page and is never counted
		if len(k.PublicKeyHash) > 0 {
			keyHashes = append(keyHashes, k.PublicKeyHash)
		}
	}
	if !strings.EqualFold(page.URL, ps.URL) || !strings.EqualFold(page.URL, p.Page) {
		return failKP(res, "the proof proves key page %s, not %s", page.URL, p.Page)
	}
	// the page hands nothing up the proof, so its chain index is fixed; the ledger hands up its root chain, which is the fourth of a system ledger's
	// chains in the order hashChains hashes them (the chain set sorted by name; measured on the simulator's BVN ledger and Kermit's Directory ledger)
	if p.PageState.Chain != 0 {
		return failKP(res, "the page proof names chain %d; it hands no chain up and must name 0", p.PageState.Chain)
	}
	if p.PartitionAnchor != nil || emptyAccountProof(&p.LedgerState) {
		return verifyAtDirectoryRoot(p, res, pin, lim, ps, page, keyHashes)
	}
	if p.Partition != "" {
		return failKP(res, "the ledger form names no partition label (the proven ledger names the partition); this proof names %q", p.Partition)
	}
	if p.LedgerState.Chain != ledgerRootChain {
		return failKP(res, "the ledger proof names chain %d, not the root chain (%d)", p.LedgerState.Chain, ledgerRootChain)
	}
	ls, err := p.LedgerState.State(lim)
	if err != nil {
		return failKP(res, "ledger state: %v", err)
	}
	ledger, err := decodeSystemLedger(p.LedgerState.MainState)
	if err != nil {
		return failKP(res, "ledger state: %v", err)
	}
	if !bytes.Equal(ps.Root, ls.Root) {
		return failKP(res, "the page and the ledger are proven in different BPT roots (%X, %X)", ps.Root, ls.Root)
	}
	if !isPartitionLedger(ledger.URL) {
		return failKP(res, "%s is not a partition's system ledger", ledger.URL)
	}
	if ledger.Index != p.Height {
		return failKP(res, "the proof is labelled height %d but the proven ledger is at block %d", p.Height, ledger.Index)
	}

	// the BPT root reaches the Directory root, which the pinned validators certified
	dirRoot, err := directoryRoot(&p.Directory, ps.Root, lim)
	if err != nil {
		return failKP(res, "%v", err)
	}
	last, err := consensus.VerifyTrace(pin, p.Consensus, lim.Consensus)
	if err != nil {
		return failKP(res, "consensus: %v", err)
	}
	if !bytes.Equal(last.Header.AppHash, dirRoot) {
		return failKP(res, "the Directory root %X is not the AppHash %X of the certified header at height %d", dirRoot, []byte(last.Header.AppHash), last.Header.Height)
	}
	res.Verified = true
	res.Form = FormLedger
	res.Page = KeyPage{URL: page.URL, AcceptThreshold: page.AcceptThreshold, Version: page.Version, KeyHashes: keyHashes}
	res.Partition, res.Height, res.BlockTime = ledger.URL, ledger.Index, ledger.Time
	res.RootAnchor = append([]byte(nil), p.LedgerState.Chains[p.LedgerState.Chain]...)
	res.DirectoryHeight = last.Header.Height
	return res
}

// isPartitionLedger: acc://<partition>.acme/ledger (protocol.PartitionUrl(id).JoinPath(protocol.Ledger)).
func isPartitionLedger(u string) bool {
	s := strings.ToLower(u)
	if !strings.HasPrefix(s, "acc://") || !strings.HasSuffix(s, ".acme/ledger") {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(s, "acc://"), ".acme/ledger")
	return id != "" && !strings.ContainsAny(id, "/.")
}

// directoryRoot applies the Directory hop to a partition value (a root or BPT anchor) and returns the Directory BPT root, with l0proof's rules: the hop
// ends in the Directory ledger's named chain, and that account is the Directory's system ledger.
func directoryRoot(h *l0proof.DirectoryHop, start []byte, lim *l0proof.Limits) ([]byte, error) {
	rootAnchor, err := h.AnchorPath.Apply(start, lim.MaxPathSteps)
	if err != nil {
		return nil, fmt.Errorf("directory anchor path: %v", err)
	}
	st, err := h.Ledger.State(lim)
	if err != nil {
		return nil, fmt.Errorf("directory ledger: %v", err)
	}
	if !bytes.Equal(h.Ledger.Chains[h.Ledger.Chain], rootAnchor) {
		return nil, fmt.Errorf("the Directory root anchor %X is not the Directory ledger's chain %d anchor", rootAnchor, h.Ledger.Chain)
	}
	if !strings.EqualFold(st.URL, l0proof.DirectoryLedgerURL) {
		return nil, fmt.Errorf("the directory hop ends in %s, not the Directory ledger %s", st.URL, l0proof.DirectoryLedgerURL)
	}
	if st.Type != accountTypeSystemLedger {
		return nil, fmt.Errorf("the Directory ledger is type %d, not a system ledger", st.Type)
	}
	return st.Root, nil
}

// ApprovalTag opens the governance WriteData's single data item: ApprovalTag ‖ planHash (32 bytes) ‖ bundleID.
const ApprovalTag = "infrix:approval:v1"

// ApprovalPayload is the data item a governance transaction carries for a plan and a bundle.
func ApprovalPayload(planHash [32]byte, bundleID string) []byte {
	b := make([]byte, 0, len(ApprovalTag)+32+len(bundleID))
	b = append(b, ApprovalTag...)
	b = append(b, planHash[:]...)
	return append(b, bundleID...)
}

// GovernanceExecution is an M-of-N approval Accumulate executed: a WriteData of the approval payload to the app's governance data account, signed under
// the app's governance key page, with the chain that proves Accumulate executed it, the signatures it accepted, and the page at the executing block.
type GovernanceExecution struct {
	// TxHash is a LABEL: the verifier recomputes the transaction hash and refuses a mismatch.
	TxHash l0proof.Bytes `json:"txHash"`
	// Signatures are the ED25519 signatures Accumulate accepted for the transaction, each in its exact binary (protocol.ED25519Signature.MarshalBinary),
	// ascending by those bytes with no repeats.
	Signatures []l0proof.Bytes `json:"signatures"`
	// Receipt proves the transaction executed (its hash on the account's main chain) and reached a certified Directory root.
	Receipt l0proof.L0ProofChain `json:"receipt"`
	// Page is the governance key page at the block that executed the transaction: the ledger form, or the directory-root form bound by the
	// partition anchor of exactly that block (main's ruling on L3170).
	Page KeyPageProof `json:"page"`
	// ExecutedBlock is a LABEL: the partition block the capture recorded as the one that executed the transaction (the entry receipt's block).
	// The directory-root form requires it and refuses an anchor of any other block; the ledger form refuses it when it differs from the proven
	// ledger's block. Zero (omitted) is accepted only with the ledger form, whose proven ledger states the block.
	ExecutedBlock uint64 `json:"executedBlock,omitempty"`
}

// GovernanceExpectation is what the RELYING PARTY expects; none of it is read from the proof.
type GovernanceExpectation struct {
	Account  string   // the app's governance data account
	Page     string   // the app's governance key page
	PlanHash [32]byte // the plan the bundle proves
	BundleID string   // the bundle
}

// GovernanceResult is the verdict on a governance execution.
type GovernanceResult struct {
	Verified bool
	Reason   string
	Pin      string
	TxHash   []byte
	Height   uint64 // the partition block that executed the transaction
	// Signers is the number of distinct page keys whose signatures verified; Threshold the page's accept threshold.
	Signers   int
	Threshold uint64
}

func failGov(format string, args ...any) GovernanceResult {
	return GovernanceResult{Reason: fmt.Sprintf(format, args...)}
}

// VerifyGovernance checks that Accumulate executed the approval: the transaction commits to the plan and the bundle and went to the governance account; its
// hash is on that account's main chain (Accumulate records it there only when it executes), reaching a certified Directory root; the governance page is
// proven AT the executing block (the page proof's ledger carries the very root-chain anchor the transaction's entry path reaches); and the accepted
// signatures, each verified here over the transaction, come from at least the page's accept threshold of distinct keys on the proven page.
func VerifyGovernance(g *GovernanceExecution, exp GovernanceExpectation, opts l0proof.Options) GovernanceResult {
	if g == nil {
		return failGov("no governance execution")
	}
	if exp.Account == "" || exp.Page == "" || exp.BundleID == "" || exp.PlanHash == ([32]byte{}) {
		return failGov("the expectation names no governance account, page, plan or bundle")
	}
	payload := ApprovalPayload(exp.PlanHash, exp.BundleID)
	if len(g.Receipt.Transaction.Entry) != 1 || !bytes.Equal(g.Receipt.Transaction.Entry[0], payload) {
		return failGov("the governance transaction does not carry exactly the approval of plan %X for bundle %s", exp.PlanHash, exp.BundleID)
	}
	chain := l0proof.Verify(&g.Receipt, l0proof.Expectation{AnchorAccount: exp.Account, Leaf: payload}, opts)
	if !chain.Verified {
		return failGov("governance receipt: %s", chain.Reason)
	}
	if !bytes.Equal(g.TxHash, chain.TxHash) {
		return failGov("the execution is labelled tx %X but the transaction hashes to %X", []byte(g.TxHash), []byte(chain.TxHash))
	}
	lim := limits(opts)
	partitionRoot, err := g.Receipt.EntryPath.Apply(chain.TxHash, lim.MaxPathSteps)
	if err != nil {
		return failGov("entry path: %v", err)
	}
	kp := VerifyKeyPage(&g.Page, opts)
	if !kp.Verified {
		return failGov("governance page: %s", kp.Reason)
	}
	if !strings.EqualFold(kp.Page.URL, exp.Page) {
		return failGov("the page proof is for %s, not the governance page %s", kp.Page.URL, exp.Page)
	}
	switch kp.Form {
	case FormDirectoryRoot:
		// the page at the executing block through its partition's anchor (main's ruling on L3170): (a) the anchor is proven on the Directory's anchor
		// pool and names the page's partition (VerifyKeyPage above), (b) its block IS the block the capture recorded as executing the transaction,
		// (c) the transaction's entry path reaches the anchor's RootChainAnchor, (d) the page is proven at the anchor's state root (VerifyKeyPage)
		if g.ExecutedBlock == 0 {
			return failGov("link (b): the execution records no executing block, so the partition anchor of block %d cannot be held to it", kp.Height)
		}
		if kp.Height != g.ExecutedBlock {
			return failGov("link (b): the partition anchor states block %d, not the block %d that executed the transaction", kp.Height, g.ExecutedBlock)
		}
		if !bytes.Equal(kp.RootAnchor, partitionRoot) {
			return failGov("link (c): the transaction's entry path reaches root anchor %X, not the partition anchor's root chain anchor %X", partitionRoot, kp.RootAnchor)
		}
	default:
		if g.ExecutedBlock != 0 && g.ExecutedBlock != kp.Height {
			return failGov("the execution records executing block %d, but the page's ledger is at block %d", g.ExecutedBlock, kp.Height)
		}
		if !bytes.Equal(kp.RootAnchor, partitionRoot) {
			return failGov("the page is proven at block %d, not at the block that executed the transaction (root anchor %X, want %X)", kp.Height, kp.RootAnchor, partitionRoot)
		}
	}
	if kp.Page.AcceptThreshold == 0 {
		return failGov("the proven page has no accept threshold")
	}
	if len(g.Signatures) > maxKeys {
		return failGov("%d signatures, over the limit of %d", len(g.Signatures), maxKeys)
	}
	// the signatures are a set, carried in one canonical order (ascending by their exact bytes, no repeats), so no reordering or repetition of a proof is
	// itself a proof
	seen := map[string]bool{}
	for i, raw := range g.Signatures {
		if i > 0 && bytes.Compare(g.Signatures[i-1], raw) >= 0 {
			return failGov("signature %d is not after signature %d in the canonical order (ascending bytes, no repeats)", i, i-1)
		}
		keyHash, err := checkSignature(raw, chain.TxHash, &kp.Page)
		if err != nil {
			return failGov("signature %d: %v", i, err)
		}
		if seen[string(keyHash)] {
			return failGov("signature %d repeats a key that already signed", i)
		}
		seen[string(keyHash)] = true
	}
	if uint64(len(seen)) < kp.Page.AcceptThreshold {
		return failGov("%d distinct page keys signed; the proven page requires %d", len(seen), kp.Page.AcceptThreshold)
	}
	return GovernanceResult{Verified: true, Pin: chain.Pin, TxHash: chain.TxHash, Height: kp.Height, Signers: len(seen), Threshold: kp.Page.AcceptThreshold}
}

// checkSignature verifies one accepted signature the way Accumulate's executor does (protocol.<Type>Signature.Verify through verifySig), for every
// user signature type an approval and its governance half may be signed as (VerifyUserSignature over SHA-256 of the metadata, the metadata being the
// signature with its value and transaction hash cleared). The signer must be the proven page at its proven version, the vote an acceptance, and the
// key on the page by the hash Accumulate computes for the type. It returns the key's hash (protocol.PublicKeyHash: KeyHash).
// Accumulate also accepts a signature over the initiator's merkle hash; a capture records the metadata form, and this verifier credits only that form.
func checkSignature(raw []byte, txHash []byte, page *KeyPage) ([]byte, error) {
	s, err := decodeUserSignature(raw)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(s.Signer, page.URL) {
		return nil, fmt.Errorf("signed by %s, not the governance page %s", s.Signer, page.URL)
	}
	if s.SignerVersion != page.Version {
		return nil, fmt.Errorf("signed at page version %d; the proven page is at version %d", s.SignerVersion, page.Version)
	}
	if s.Vote != voteTypeAccept {
		return nil, fmt.Errorf("the signature votes %d, not accept", s.Vote)
	}
	if s.TxHash != nil && !bytes.Equal(s.TxHash, txHash) {
		return nil, errors.New("the signature names a different transaction")
	}
	md := sha256.Sum256(s.Metadata)
	if err := VerifyUserSignature(s.Type, s.PublicKey, s.Signature, md[:], txHash, s.Timestamp); err != nil {
		return nil, fmt.Errorf("%w over the transaction", err)
	}
	kh, err := KeyHash(s.Type, s.PublicKey)
	if err != nil {
		return nil, err
	}
	if !page.Has(kh) {
		return nil, fmt.Errorf("%s key %X is not on the proven page %s", s.Type, kh, page.URL)
	}
	return kh, nil
}
