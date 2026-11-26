// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-verify/govproof"
	"github.com/opendlt/infrix-verify/l0proof"
)

// THE EMBEDDED ACCUMULATE PROOFS (the native proof plan, phases 5 and 7; brief 28bh).
//
//   - embedded_l0_proof (L4, source embedded-proof): the bundle's l0Proof is an l0proof.L0ProofChain proving the batch root its anchor inclusion names
//     is the single data item of a WriteData Accumulate executed, carried to a Directory header certified from the verifier's OWN pin (Options.L0Network's
//     compiled pin, or an explicit Options.L0Pin). Never the bundle's.
//   - approval_key_pages (G1): every approval's key is proven on the key page its signed preimage names, by a govproof.KeyPageProof the verifier checks
//     against the same pin; the page's version is the version the approver signed against (the preimage's signer version, so the key set the proof shows
//     is the key set at signing); and on every page, the distinct approving keys reach the threshold the PROVEN page states.
//   - governance_execution (G2): Accumulate itself executed the M-of-N approval of this plan for this bundle under the governance page and account the
//     RELYING PARTY names (Options.GovernancePage, Options.GovernanceAccount), proven by govproof.VerifyGovernance.

// l0Opts is the trust root every embedded proof is checked against.
func l0Opts(opts Options) l0proof.Options {
	network := opts.L0Network
	if network == "" {
		network = l0proof.NetworkKermit
	}
	return l0proof.Options{Network: network, OverridePin: opts.L0Pin}
}

// PinFlagHint is how a relying party passes a pin the verifier does not compile in (brief 28bl row 1): a local run writes its network's pin next
// to its bundle, and the verifier takes it only when the relying party passes it explicitly.
const PinFlagHint = "pass that network's pin explicitly (infrix verify --l0-pin <pin file>; a local run writes pin.local-embedded.json next to its bundle)"

// unheldPin names the pin a proof was captured under when the relying party passed NO pin and the proof's incarnation is not the compiled pin of the
// network the verifier was told to use (brief 28bl row 1). Such a proof cannot be judged at all, because the verifier holds no trust root for it: it is
// not credited, and the report names the pin the relying party must pass to judge it. It is never credited from the bundle. With an explicit pin, a
// mismatch is a refusal (the proof's own verification fails), never this.
func unheldPin(incarnation string, opts Options) (string, bool) {
	if opts.L0Pin != nil {
		return "", false
	}
	o := l0Opts(opts)
	pin, err := l0proof.CompiledPin(o.Network)
	if err != nil || incarnation == pin.ID() {
		return "", false
	}
	return fmt.Sprintf("captured under pin %q, which this verifier does not hold (its trust root is the compiled %s pin %q): %s", incarnation, o.Network, pin.ID(), PinFlagHint), true
}

// txPrincipal reads a transaction header's principal (field 1, a URL): the anchor account the WriteData names. The account adds no trust: what L4 proves
// is that this batch root was written to Accumulate by a transaction Accumulate executed before a certified Directory height.
func txPrincipal(header []byte) string {
	if len(header) < 2 || header[0] != 1 {
		return ""
	}
	n, k := binary.Uvarint(header[1:])
	if k <= 0 || n > uint64(len(header)-1-k) {
		return ""
	}
	return string(header[1+k : 1+k+int(n)])
}

func (r *Report) checkEmbeddedL0Proof(bundle *evidence.EvidenceBundle, parsed, anchored bool, opts Options) bool {
	const name = "embedded_l0_proof"
	if !parsed || len(bundle.L0Proof) == 0 {
		r.add(name, CheckSkip, "the bundle embeds no L0 proof chain (proof level caps at L3 offline)")
		return false
	}
	if !anchored || bundle.AnchorInclusion == nil {
		r.add(name, CheckFail, "the bundle embeds an L0 proof chain but no verified inclusion of its hash in a batch root")
		return false
	}
	chain, err := l0proof.Decode(bundle.L0Proof, nil)
	if err != nil {
		r.add(name, CheckFail, err.Error())
		return false
	}
	if why, unheld := unheldPin(chain.Incarnation, opts); unheld {
		r.add(name, CheckSkip, "the L0 proof chain was "+why+" (proof level caps at L3 offline)")
		return false
	}
	root := bundle.AnchorInclusion.BatchRoot
	res := l0proof.Verify(chain, l0proof.Expectation{AnchorAccount: txPrincipal(chain.Transaction.Header), Leaf: root[:]}, l0Opts(opts))
	if !res.Verified {
		r.add(name, CheckFail, res.Reason)
		return false
	}
	pinNote := "compiled pin"
	if res.PinOverridden {
		pinNote = "relying-party pin"
	}
	r.add(name, CheckPass, fmt.Sprintf("batch root %x anchored by tx %x, certified at Directory height %d (%s network %s, %s %s)", root, []byte(res.TxHash), res.DirectoryHeight, pinNote, res.Network, "pin", res.Pin))
	return true
}

// checkApprovalKeyPages returns whether every approval's key is proven on its page at signing and every page's threshold is met from the proven page. It
// runs only when every approval's signature already verified (approvalsSigned).
func (r *Report) checkApprovalKeyPages(bundle *evidence.EvidenceBundle, approvalsSigned bool, opts Options) bool {
	const name = "approval_key_pages"
	if !approvalsSigned {
		r.add(name, CheckSkip, "no verified approval signatures to prove on key pages (governance caps at G0)")
		return false
	}
	if len(bundle.KeyPageProofs) == 0 {
		r.add(name, CheckSkip, "the bundle embeds no key-page proofs: no approver key is proven on its page (governance caps at G0)")
		return false
	}
	pages := map[string]*govproof.KeyPageResult{}
	for i, raw := range bundle.KeyPageProofs {
		var p govproof.KeyPageProof
		if err := decodeStrict(raw, &p); err != nil {
			r.add(name, CheckFail, fmt.Sprintf("key-page proof %d: %v", i, err))
			return false
		}
		if why, unheld := unheldPin(p.Incarnation, opts); unheld {
			r.add(name, CheckSkip, fmt.Sprintf("key-page proof %d was %s (governance caps at G0)", i, why))
			return false
		}
		res := govproof.VerifyKeyPage(&p, l0Opts(opts))
		if !res.Verified {
			r.add(name, CheckFail, fmt.Sprintf("key-page proof %d: %s", i, res.Reason))
			return false
		}
		key := strings.ToLower(res.Page.URL)
		if pages[key] != nil {
			r.add(name, CheckFail, fmt.Sprintf("key-page proof %d repeats page %s", i, res.Page.URL))
			return false
		}
		pages[key] = &res
	}
	signers := map[string]map[string]bool{}
	for i, ae := range bundle.ApprovalEvidence {
		pre, err := decodeApprovalPreimage(ae.SignedPreimage)
		if err != nil {
			r.add(name, CheckFail, fmt.Sprintf("approval %d: %v", i, err))
			return false
		}
		page := pages[strings.ToLower(pre.KeyPageRef)]
		if page == nil {
			r.add(name, CheckSkip, fmt.Sprintf("approval %d names key page %s, which no embedded proof proves (governance caps at G0)", i, pre.KeyPageRef))
			return false
		}
		if !pre.UserSignature {
			r.add(name, CheckSkip, fmt.Sprintf("approval %d is a bare %s signature, which commits to no page version, so its key cannot be proven on the page at signing (governance caps at G0)", i, ae.SigType))
			return false
		}
		kh, err := govproof.KeyHash(strings.TrimPrefix(ae.SigType, evidence.ApprovalSigTypeAccumulatePrefix), pre.PublicKey)
		if err != nil {
			r.add(name, CheckSkip, fmt.Sprintf("approval %d: %v (governance caps at G0)", i, err))
			return false
		}
		if pre.SignerVersion != page.Page.Version {
			// credit only the page proven at EXACTLY the version the signature claims: the version changes on every key change, so that state pins the
			// exact key set the signature claims (main ruling 2026-11-26)
			r.add(name, CheckFail, fmt.Sprintf("approval %d signed against version %d of %s; the proven page is at version %d", i, pre.SignerVersion, page.Page.URL, page.Page.Version))
			return false
		}
		if !page.Page.Has(kh) {
			r.add(name, CheckFail, fmt.Sprintf("approval %d's key %x is not on the proven page %s", i, kh, page.Page.URL))
			return false
		}
		k := strings.ToLower(page.Page.URL)
		if signers[k] == nil {
			signers[k] = map[string]bool{}
		}
		signers[k][string(kh)] = true
	}
	var urls []string
	for k := range signers {
		urls = append(urls, k)
	}
	sort.Strings(urls)
	var met []string
	for _, k := range urls {
		p := pages[k]
		if p.Page.AcceptThreshold == 0 || uint64(len(signers[k])) < p.Page.AcceptThreshold {
			r.add(name, CheckSkip, fmt.Sprintf("%d distinct key(s) of %s approved; the proven page requires %d (governance caps at G0)", len(signers[k]), p.Page.URL, p.Page.AcceptThreshold))
			return false
		}
		met = append(met, fmt.Sprintf("%s %d-of-%d at block %d", p.Page.URL, len(signers[k]), p.Page.AcceptThreshold, p.Height))
	}
	if len(pages) != len(signers) {
		r.add(name, CheckFail, "the bundle embeds a key-page proof for a page no approval names")
		return false
	}
	r.add(name, CheckPass, "version-bound (off-chain): every approver key proven on its page at exactly its signed version (a key removed later and backdating its version is not excluded; only an Accumulate-executed approval excludes that): "+strings.Join(met, "; "))
	return true
}

func (r *Report) checkGovernanceExecution(bundle *evidence.EvidenceBundle, planHash [32]byte, parsed bool, opts Options) bool {
	const name = "governance_execution"
	if !parsed || len(bundle.GovernanceExecution) == 0 {
		r.add(name, CheckSkip, "the bundle embeds no Accumulate-executed approval (governance caps at G1)")
		return false
	}
	if opts.GovernancePage == "" || opts.GovernanceAccount == "" {
		r.add(name, CheckSkip, "the relying party named no governance page and account to hold the execution to (governance caps at G1)")
		return false
	}
	var g govproof.GovernanceExecution
	if err := decodeStrict(bundle.GovernanceExecution, &g); err != nil {
		r.add(name, CheckFail, err.Error())
		return false
	}
	if why, unheld := unheldPin(g.Receipt.Incarnation, opts); unheld {
		r.add(name, CheckSkip, "the governance execution was "+why+" (governance caps at G1)")
		return false
	}
	res := govproof.VerifyGovernance(&g, govproof.GovernanceExpectation{Account: opts.GovernanceAccount, Page: opts.GovernancePage, PlanHash: planHash, BundleID: bundle.ID}, l0Opts(opts))
	if !res.Verified {
		r.add(name, CheckFail, res.Reason)
		return false
	}
	r.add(name, CheckPass, fmt.Sprintf("Accumulate executed the %d-of-%d approval (tx %x) at block %d under %s (pin %s)", res.Signers, res.Threshold, res.TxHash, res.Height, opts.GovernancePage, res.Pin))
	return true
}

// decodeStrict decodes one embedded proof, refusing an unknown field, trailing data and an encoding over l0proof's size limit.
func decodeStrict(raw []byte, v any) error {
	if len(raw) > l0proof.DefaultLimits.MaxProofBytes {
		return fmt.Errorf("%w: %d bytes", l0proof.ErrProofTooLarge, len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the proof")
	}
	return nil
}
