// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

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

// THE PAGE AT A DIRECTORY-RECORDED ROOT (core KNOWN-LIMITS L3168, main's ruling 2026-11-27). A partition that goes idle anchors its latest BPT root
// only with its next activity, and a network may serve a key page's historical state proof while refusing its partition ledger's (Kermit today: the
// ledger's historical receipt fails with "uncommitted changes", fixed only by the fork patch accumulate-ledger-historical-receipt.patch). The
// ledger-carrying KeyPageProof then cannot be taken after a restart or on an idle partition. This form proves the page at a root the Directory has
// ALREADY recorded, with no ledger:
//
//	page state         -- PageState.StatePath ------------> the partition BPT root V
//	anchor transaction -- (its body)                       the partition's BlockValidatorAnchor: Source names the partition, StateTreeAnchor is V,
//	                                                       MinorBlockIndex the block whose root V is. Its hash is recomputed from the carried header
//	                                                       and body; its header's principal must be the Directory's anchor pool (acc://dn.acme/anchors)
//	tx hash            -- PartitionAnchor.EntryPath ------> the Directory root-chain anchor of the block that executed it (the anchor pool's main
//	                                                       chain, then the Directory root chain; Accumulate records a transaction hash on its
//	                                                       principal's main chain only when it executes it, and the anchor pool executes only the
//	                                                       anchors the partitions' validators sign)
//	Directory anchor   -- Directory.AnchorPath -----------> the Directory root-chain anchor the Directory ledger states (anchor(directory)-root)
//	Directory root     -- Directory.Ledger ---------------> the Directory BPT root == the AppHash of a header certified from the pin.
//
// The anchor transaction binds the PARTITION (an anchor-chain entry alone proves only that V is an element of some Directory chain, since an account
// hash covers chain anchors, not chain names) and proves the block index. The verifier credits the page's keys at that Directory-certified root of
// the partition, and the block height exactly as the anchor states it: the minor block whose BPT root the partition anchored as V. The block's time is
// not in the anchor, so it is named UNPROVEN and never claimed. The anchor also states the partition's root-chain anchor at that block
// (RootChainAnchor), which the verdict carries: a governance execution holds its transaction's entry path to it and its executing block to the
// anchor's block, so this form proves the page AT the executing block (G2, main's ruling on L3170) exactly when every link holds.

// Forms of a KeyPageProof (KeyPageResult.Form).
const (
	// FormLedger is the page and its partition's system ledger in one BPT root (the ledger names the block and its time).
	FormLedger = "page_with_ledger"
	// FormDirectoryRoot is the page at a BPT root its partition anchored on the Directory, bound by the partition's anchor transaction.
	FormDirectoryRoot = "page_at_directory_root"
)

// UnprovenBlockTime is what a directory-root proof names unproven: the anchor carries the block index, not the block's time.
const UnprovenBlockTime = "block time"

// HeightByPartitionAnchor is how a directory-root proof's height is proven (KeyPageResult.HeightProvenBy).
const HeightByPartitionAnchor = "the minor block index of the partition's BlockValidatorAnchor that states the BPT root"

// directoryAnchorPool is the Directory's anchor pool (protocol.DnUrl().JoinPath(protocol.AnchorPool)), the principal of every partition anchor the
// Directory executes.
const directoryAnchorPool = "acc://dn.acme/anchors"

// transactionTypeBlockValidatorAnchor is protocol.TransactionTypeBlockValidatorAnchor.
const transactionTypeBlockValidatorAnchor = 98

// PartitionAnchor proves a partition's BlockValidatorAnchor executed on the Directory: the transaction in its exact binary and the entry path of its
// hash to the Directory root-chain anchor of the block that executed it.
type PartitionAnchor struct {
	Transaction AnchorTx     `json:"transaction"`
	EntryPath   l0proof.Path `json:"entryPath"`
}

// AnchorTx is a partition anchor transaction in the exact Accumulate binary the Directory hashed: TransactionHeader.MarshalBinary and
// BlockValidatorAnchor.MarshalBinary (its hash is SHA-256(SHA-256(header) ‖ SHA-256(body)), protocol/transaction_hash.go).
type AnchorTx struct {
	Header l0proof.Bytes `json:"header"`
	Body   l0proof.Bytes `json:"body"`
}

// blockAnchor is what a BlockValidatorAnchor body states (protocol.BlockValidatorAnchor: 1 type, 2 the PartitionAnchor value (1 source, 2 major block
// index, 3 minor block index, 4 root chain index, 5 root chain anchor, 6 state tree anchor), 3 ACME burnt).
type blockAnchor struct {
	Source          string
	MinorBlockIndex uint64
	RootChainAnchor []byte
	StateTreeAnchor []byte
}

func decodeBlockValidatorAnchor(body []byte) (*blockAnchor, error) {
	r := &reader{b: body}
	f, err := r.next(0, "anchor body")
	if err != nil {
		return nil, err
	}
	if f != 1 {
		return nil, fmt.Errorf("anchor body: field %d where the type is required", f)
	}
	t, err := r.uvarint("anchor body type")
	if err != nil {
		return nil, err
	}
	if t != transactionTypeBlockValidatorAnchor {
		return nil, fmt.Errorf("the anchor transaction is type %d, not a BlockValidatorAnchor (%d)", t, transactionTypeBlockValidatorAnchor)
	}
	var pa []byte
	prev := uint64(1)
	for !r.done() {
		f, err := r.next(prev, "anchor body")
		if err != nil {
			return nil, err
		}
		prev = f
		switch f {
		case 2:
			if pa, err = r.bytes("partition anchor"); err != nil {
				return nil, err
			}
		case 3:
			if _, err := r.bytes("ACME burnt"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the anchor body has unknown field %d", f)
		}
	}
	if pa == nil {
		return nil, errors.New("the anchor body carries no partition anchor")
	}
	a := &blockAnchor{}
	pr := &reader{b: pa}
	prev = 0
	for !pr.done() {
		f, err := pr.next(prev, "partition anchor")
		if err != nil {
			return nil, err
		}
		prev = f
		switch f {
		case 1:
			u, err := pr.bytes("anchor source")
			if err != nil {
				return nil, err
			}
			a.Source = string(u)
		case 2, 4:
			if _, err := pr.uvarint("anchor block or chain index"); err != nil {
				return nil, err
			}
		case 3:
			if a.MinorBlockIndex, err = pr.uvarint("anchor minor block index"); err != nil {
				return nil, err
			}
		case 5:
			if a.RootChainAnchor, err = pr.raw(32, "anchor root chain anchor"); err != nil {
				return nil, err
			}
		case 6:
			if a.StateTreeAnchor, err = pr.raw(32, "anchor state tree anchor"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the partition anchor has unknown field %d", f)
		}
	}
	if a.Source == "" || a.MinorBlockIndex == 0 || a.StateTreeAnchor == nil || a.RootChainAnchor == nil {
		return nil, errors.New("the partition anchor names no source, minor block or state tree anchor")
	}
	return a, nil
}

// txHeaderPrincipal reads a transaction header's principal (field 1, a URL).
func txHeaderPrincipal(header []byte) (string, error) {
	r := &reader{b: header}
	f, err := r.next(0, "transaction header")
	if err != nil {
		return "", err
	}
	if f != 1 {
		return "", fmt.Errorf("transaction header: field %d where the principal is required", f)
	}
	u, err := r.bytes("transaction principal")
	if err != nil {
		return "", err
	}
	if len(u) == 0 {
		return "", errors.New("the transaction principal is empty")
	}
	return string(u), nil
}

// partitionURL is protocol.PartitionUrl(id) for a BVN: acc://bvn-<id>.acme (compared case-insensitively, as url.URL.Equal does).
func partitionURL(id string) string { return "acc://bvn-" + id + ".acme" }

// emptyAccountProof reports an AccountProof carrying nothing (the directory-root form carries no ledger).
func emptyAccountProof(a *l0proof.AccountProof) bool {
	return len(a.MainState) == 0 && len(a.SecondaryState) == 0 && len(a.Chains) == 0 && a.Chain == 0 && len(a.Pending) == 0 && len(a.StatePath) == 0
}

// verifyAtDirectoryRoot checks a directory-root key-page proof. The page has already been decoded and its proven URL matched to the label (ps, page,
// keyHashes); res carries the pin.
func verifyAtDirectoryRoot(p *KeyPageProof, res KeyPageResult, pin *consensus.Pin, lim *l0proof.Limits, ps *l0proof.AccountState, page *l0proof.KeyPage, keyHashes [][]byte) KeyPageResult {
	if !emptyAccountProof(&p.LedgerState) {
		return failKP(res, "the proof carries both a partition ledger and a partition anchor; a key-page proof takes one form")
	}
	if p.PartitionAnchor == nil || (len(p.PartitionAnchor.Transaction.Header) == 0 && len(p.PartitionAnchor.Transaction.Body) == 0) {
		return failKP(res, "the proof carries no partition ledger and no partition anchor transaction: neither its partition nor its block height is proven, and nothing is credited")
	}
	if p.Partition == "" || strings.EqualFold(p.Partition, "directory") || strings.ContainsAny(p.Partition, "/.:") {
		return failKP(res, "the directory-root proof names no BVN partition (%q)", p.Partition)
	}
	tx := &p.PartitionAnchor.Transaction
	if len(tx.Header)+len(tx.Body) > lim.MaxTransactionBytes {
		return failKP(res, "the anchor transaction is %d bytes, over the limit of %d", len(tx.Header)+len(tx.Body), lim.MaxTransactionBytes)
	}
	principal, err := txHeaderPrincipal(tx.Header)
	if err != nil {
		return failKP(res, "anchor transaction: %v", err)
	}
	if !strings.EqualFold(principal, directoryAnchorPool) {
		return failKP(res, "the anchor transaction's principal is %s, not the Directory's anchor pool %s", principal, directoryAnchorPool)
	}
	a, err := decodeBlockValidatorAnchor(tx.Body)
	if err != nil {
		return failKP(res, "anchor transaction: %v", err)
	}
	if !strings.EqualFold(a.Source, partitionURL(p.Partition)) {
		return failKP(res, "the anchor names partition %s, not the proof's partition %s", a.Source, partitionURL(p.Partition))
	}
	if !bytes.Equal(a.StateTreeAnchor, ps.Root) {
		return failKP(res, "the page is proven in BPT root %X, but the partition's anchor states root %X", ps.Root, a.StateTreeAnchor)
	}
	if a.MinorBlockIndex != p.Height {
		return failKP(res, "the proof is labelled height %d but the partition's anchor states block %d", p.Height, a.MinorBlockIndex)
	}
	hh := sha256.Sum256(tx.Header)
	bh := sha256.Sum256(tx.Body)
	txHash := sha256.Sum256(append(hh[:], bh[:]...))
	dirAnchor, err := p.PartitionAnchor.EntryPath.Apply(txHash[:], lim.MaxPathSteps)
	if err != nil {
		return failKP(res, "anchor entry path: %v", err)
	}
	dirRoot, err := directoryRoot(&p.Directory, dirAnchor, lim)
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
	res.Form = FormDirectoryRoot
	res.Page = KeyPage{URL: page.URL, AcceptThreshold: page.AcceptThreshold, Version: page.Version, KeyHashes: keyHashes}
	res.Partition = strings.ToLower(a.Source) + "/ledger"
	res.Height, res.HeightProvenBy = a.MinorBlockIndex, HeightByPartitionAnchor
	res.Unproven = []string{UnprovenBlockTime}
	res.RootAnchor = append([]byte(nil), a.RootChainAnchor...)
	res.DirectoryHeight = last.Header.Height
	return res
}
