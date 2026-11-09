// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package stateroot is the verifier's side of the node's STATE ROOT HISTORY: it decides whether an evidence bundle's state root is a root the node actually held,
// that THIS bundle was bound to it, and when, by an inclusion proof into a root-history seal the node anchored to L0.
//
// WHY. A bundle carries the node's state root as of its own finalization. The node anchors its state root only every N canonical blocks (and only when it
// changed), so almost no bundle's root is a root any anchor names, and a verifier that demanded it be the anchored root would refuse nearly every honest bundle. The
// node therefore keeps an append-only Merkle tree of every root it held and of every consumption of one, anchors the sealed root of that tree, and an exported
// bundle carries an inclusion proof of ITS leaf against an anchored seal. A root the node never held is in no anchored seal, and a leaf recorded for another bundle
// is not this bundle's.
//
// THE TREE is the RFC 9162 Merkle tree over two kinds of leaf, told apart by the length of what they hash:
//
//	a root-change leaf  SHA-256(0x00 || be64(height) || root)                       40 bytes of leaf data
//	a consumer leaf     SHA-256(0x00 || be64(height) || root || consumerDigest)     72 bytes of leaf data
//	consumerDigest      SHA-256("infrix-root-consumer-v1" || id)
//
// and node = SHA-256(0x01 || left || right), a node over n leaves splitting at the largest power of two below n. The SEALED ROOT the node anchors is
// SHA-256("infrix-root-history-v1" || be64(n) || treeHash), so what is anchored commits to the leaf count as well as the tree. The consumer of a bundle's leaf is
// the bundle's own outcome id: the leaf is the moment the node read its root to finalize THAT outcome, so the proof binds the bundle to the leaf with no slack.
//
// WHEN. The leaf's canonical height is the node's own statement. The check dates it from L0: it cannot be later than the last canonical height of the anchor batch
// that covers its seal, and it cannot be earlier than the first height of the PRIOR anchored window, which the document names with a CONSISTENCY PROOF (RFC 9162
// section 2.1.4) that the prior seal's tree is a prefix of the covering one, so that "this leaf was appended after the prior anchor" is a fact about one history and
// not about two. The lower edge is as tight as the prior the node names: a node may name an older anchor than the immediate predecessor and widen its own span,
// which loosens the bound and never falsifies it.
//
// THIS IMPLEMENTATION IS INDEPENDENT ON PURPOSE. The node builds the tree and makes proofs in the Infrix runtime module (pkg/rootaccum), which this module must not
// import (the verifier isolation fence), so the check is written again here, from the same specification, and the two are pinned by ONE file of vectors the runtime
// repository generates and both repositories' tests read (testdata/state-root-vectors.json): every leaf hash, the seal of every tree size to 40, the audit path of
// every leaf of every size, the consistency proof between every pair of sizes, the compact range of every tree size (the checkpoints) and a table of document cases, a
// tamper case for every outcome of Check's rule. This package only verifies; it never builds a tree.
//
// THE CHECKPOINT STATEMENT (ledger L1647). A node that checkpointed its root history dropped the leaves before the checkpoint, so a bundle recorded before it can only be
// proven by the document exported with it, and the node answers any other such bundle with an UNAVAILABLE document that carries its own statement of the checkpoint: the
// number of leaves sealed, the canonical height of the last of them, the sealed root over them, the compact range of their tree (the perfect subtrees of the binary
// decomposition of the size, left to right) and, when it knows it, the L0 anchor of that seal. The statement proves NOTHING about the bundle, so it is never a pass; what it
// can be is FALSE, and a false one is a FAIL: the compact range must be the decomposition of the size, fold (the last subtree, then each earlier one hashed over the rest)
// to the tree hash, and the seal of the size and that hash must be the sealed root the statement names. A statement that holds is a SKIP saying so; with an L0 reader and an
// anchor named, L0 must list the sealed root.
package stateroot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// SealDomain is the domain tag of the sealed root.
const SealDomain = "infrix-root-history-v1"

// ConsumerDomain is the domain tag of a consumer's digest.
const ConsumerDomain = "infrix-root-consumer-v1"

// DocumentVersion identifies the wire form of Document this package reads.
const DocumentVersion = "infrix-state-root-proof-v2"

// documentVersionV1 is the form the node wrote before leaves named their consumer. It proves a root was held and nothing about which bundle read it, so it is
// never a pass: the check skips it by name.
const documentVersionV1 = "infrix-state-root-proof-v1"

// DocumentKey is the top-level JSON key under which a Document travels beside an exported evidence package: a sibling of the package's own fields, so the package's
// export hash and every other check on it are untouched, and a package without the key is judged exactly as before.
const DocumentKey = "stateRootProof"

// CheckName is the name the check carries in a verifykit report.
const CheckName = "state_root_accumulator"

// Status says how far a bundle's state root has got toward being checkable.
type Status string

const (
	// StatusProven: the document carries an inclusion proof against a seal the node anchored, and where the anchor is.
	StatusProven Status = "proven"
	// StatusAwaitingAnchor: the root is in the node's history but newer than the newest anchored seal; it becomes provable once the next seal is anchored.
	StatusAwaitingAnchor Status = "awaiting_anchor"
	// StatusUnavailable: no proof can be made; Reason says why.
	StatusUnavailable Status = "unavailable"
)

// AnchorRef locates the L0 transaction that anchored a sealed root.
type AnchorRef struct {
	TxHash        string `json:"txHash"`
	Account       string `json:"account,omitempty"`
	L0BlockHeight uint64 `json:"l0BlockHeight,omitempty"`
}

// Prior names the anchor that preceded the one covering the leaf, and proves its tree is a prefix of the covering one.
type Prior struct {
	Anchor          *AnchorRef `json:"anchor,omitempty"`
	AccumulatorRoot string     `json:"accumulatorRoot,omitempty"` // the prior sealed root, as L0 lists it
	TreeSize        uint64     `json:"treeSize,omitempty"`        // the number of leaves the prior seal commits to
	MTH             string     `json:"mth,omitempty"`             // the prior tree's hash, so the seal can be recomputed from size and hash
	Consistency     []string   `json:"consistency,omitempty"`     // the RFC 9162 consistency proof from the prior tree to the covering one
}

// Document is what an export attaches beside a bundle: an inclusion proof of the bundle's own leaf against an anchored seal, or the reason there is none yet. All
// hashes are lowercase hex.
type Document struct {
	Version   string `json:"version"`
	Status    Status `json:"status"`
	StateRoot string `json:"stateRoot"`
	Reason    string `json:"reason,omitempty"`

	// Consumer is the id the leaf was recorded for; the verifier recomputes the digest from it.
	Consumer string `json:"consumer,omitempty"`

	LeafHeight      uint64     `json:"leafHeight,omitempty"`
	LeafIndex       uint64     `json:"leafIndex,omitempty"`
	TreeSize        uint64     `json:"treeSize,omitempty"`
	Path            []string   `json:"path,omitempty"`
	AccumulatorRoot string     `json:"accumulatorRoot,omitempty"`
	Anchor          *AnchorRef `json:"anchor,omitempty"`
	Prior           *Prior     `json:"prior,omitempty"`

	CurrentSize        uint64 `json:"currentSize,omitempty"`
	NewestAnchoredSize uint64 `json:"newestAnchoredSize,omitempty"`

	// Checkpoint, on an unavailable document, is the node's own statement that it checkpointed its root history (ledger L1647): leaves before Size are no longer held, so a bundle recorded
	// before it can only be proven by the document exported with it. A verifier checks the statement against the seal it names; it never reads it as a proof of the bundle.
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// Checkpoint is a checkpoint as an unavailable document states it: the number of leaves sealed and dropped, the canonical height of the last of them, the sealed root over them (the
// value the node pinned for an anchor and L0 holds), the compact range of their tree (the perfect subtrees of the binary decomposition of Size, left to right, lowercase hex) and, when
// the node knows it, the L0 anchor of that seal.
type Checkpoint struct {
	Size       uint64     `json:"size"`
	LastHeight uint64     `json:"lastHeight"`
	SealedRoot string     `json:"sealedRoot"`
	Compact    []string   `json:"compact"`
	Anchor     *AnchorRef `json:"anchor,omitempty"`
}

// Verify checks the checkpoint against itself: the compact range must be the decomposition of Size (as many entries as Size has one bits, each of the width the bits give) and fold to
// the tree hash the sealed root commits to together with Size. A checkpoint that fails names a range for another tree, or a seal for another size.
func (c *Checkpoint) Verify() error {
	if c.Size == 0 {
		return errors.New("the checkpoint seals no leaves")
	}
	sealed, err := decode32(c.SealedRoot)
	if err != nil {
		return fmt.Errorf("sealedRoot: %w", err)
	}
	var hashes [][32]byte
	rest := c.Size
	for i, s := range c.Compact {
		if rest == 0 {
			return fmt.Errorf("the compact range has more entries than the %d leaves it covers have subtrees", c.Size)
		}
		h, err := decode32(s)
		if err != nil {
			return fmt.Errorf("compact[%d]: %w", i, err)
		}
		hashes = append(hashes, h)
		rest -= uint64(1) << (bits.Len64(rest) - 1) // the largest power of two in what is left: the next perfect subtree
	}
	if rest != 0 {
		return fmt.Errorf("a tree of %d leaves has a compact range of %d subtrees, not %d", c.Size, bits.OnesCount64(c.Size), len(hashes))
	}
	folded := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		folded = nodeHash(hashes[i], folded)
	}
	if seal(c.Size, folded) != sealed {
		return errors.New("the compact range does not fold to the sealed root")
	}
	return nil
}

// AnchorEntry is what L0 holds for one anchor transaction: the roots the batch entry lists and the canonical window of that batch. Both heights zero means the
// entry carries no window (the privacy closure zeroes per-entry heights but keeps the batch's first and last).
type AnchorEntry struct {
	Roots       [][32]byte
	FirstHeight uint64
	LastHeight  uint64
}

// HasWindow reports whether the entry carries a canonical window.
func (e AnchorEntry) HasWindow() bool { return e.FirstHeight != 0 || e.LastHeight != 0 }

// Lists reports whether the entry lists the sealed root.
func (e AnchorEntry) Lists(sealed [32]byte) bool {
	for _, r := range e.Roots {
		if r == sealed {
			return true
		}
	}
	return false
}

// AnchorReader reads what L0 holds. AnchorAt returns the anchor entry of the L0 transaction txHash, taken from L0 itself, never from the node that produced the
// bundle. It is the verifier's port, injected by the application like verifykit's L0AnchorConfirmer.
type AnchorReader interface {
	AnchorAt(ctx context.Context, txHash string) (AnchorEntry, error)
}

// Verdict is the outcome of Check.
type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictFail Verdict = "fail"
	VerdictSkip Verdict = "skip"
)

// Result is a verdict and the sentence that says why.
type Result struct {
	Verdict Verdict
	Detail  string
}

// ErrBadProof is returned for a proof that does not prove inclusion or consistency.
var ErrBadProof = errors.New("stateroot: the proof does not prove inclusion")

// ConsumerDigest is SHA-256(ConsumerDomain || id).
func ConsumerDigest(id string) [32]byte {
	h := sha256.New()
	h.Write([]byte(ConsumerDomain))
	h.Write([]byte(id))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// leafHash hashes a root-change leaf (consumer == "") or a consumer leaf.
func leafHash(height uint64, root [32]byte, consumer string) [32]byte {
	b := make([]byte, 0, 73)
	b = append(b, 0x00)
	b = binary.BigEndian.AppendUint64(b, height)
	b = append(b, root[:]...)
	if consumer != "" {
		d := ConsumerDigest(consumer)
		b = append(b, d[:]...)
	}
	return sha256.Sum256(b)
}

func nodeHash(left, right [32]byte) [32]byte {
	var b [65]byte
	b[0] = 0x01
	copy(b[1:33], left[:])
	copy(b[33:], right[:])
	return sha256.Sum256(b[:])
}

func seal(size uint64, treeHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(SealDomain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], size)
	h.Write(n[:])
	h.Write(treeHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SealedRootOf recomputes the sealed root a proof commits to from its leaf and audit path alone (RFC 9162 section 2.1.3.2), for leaf number index of a tree of size
// leaves. consumer is "" for a root-change leaf. It fails for a path of the wrong length for that index and size.
func SealedRootOf(index, size, height uint64, root [32]byte, consumer string, path [][32]byte) ([32]byte, error) {
	if size == 0 || index >= size {
		return [32]byte{}, ErrBadProof
	}
	fn, sn := index, size-1
	acc := leafHash(height, root, consumer)
	for _, sib := range path {
		if sn == 0 {
			return [32]byte{}, ErrBadProof
		}
		if fn&1 == 1 || fn == sn {
			acc = nodeHash(sib, acc)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			acc = nodeHash(acc, sib)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return [32]byte{}, ErrBadProof
	}
	return seal(size, acc), nil
}

// VerifyConsistency checks an RFC 9162 section 2.1.4.2 consistency proof that the tree of `first` leaves with hash firstHash is a prefix of a tree of `second`
// leaves, and returns the hash of the second tree the proof computes. It does not decide that the second hash is the one anyone anchored: the caller compares the
// seal of it.
func VerifyConsistency(first, second uint64, firstHash [32]byte, path [][32]byte) ([32]byte, error) {
	if first == 0 || first > second {
		return [32]byte{}, ErrBadProof
	}
	if first == second {
		if len(path) != 0 {
			return [32]byte{}, ErrBadProof
		}
		return firstHash, nil
	}
	if first&(first-1) == 0 { // an exact power of two: the first tree's hash is the first node of the path
		path = append([][32]byte{firstHash}, path...)
	}
	if len(path) == 0 {
		return [32]byte{}, ErrBadProof
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return [32]byte{}, ErrBadProof
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || fr != firstHash {
		return [32]byte{}, ErrBadProof
	}
	return sr, nil
}

func decode32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%d bytes, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func decodePath(in []string) ([][32]byte, error) {
	out := make([][32]byte, len(in))
	for i, s := range in {
		h, err := decode32(s)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = h
	}
	return out, nil
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

// Check is the verifier's judgement of a bundle's state root against an attached document, for a bundle whose consumer id (its outcome id) is consumerID. The rule:
//
//   - no document (every bundle exported before the node kept a root history): SKIP, and the verdict the verifier reached is exactly what it was.
//   - a document that is awaiting an anchor or unavailable: SKIP, with the reason. A bundle finalized after the newest anchor is "unchecked until the next anchor".
//   - a version 1 document, or a proven one that names no consumer: SKIP, "no consumer recorded": it proves the root was held and not that THIS bundle read it, and
//     a verifier that passed it would say more than it knows. A version it does not read is a SKIP too. A bundle that names no id cannot be bound: SKIP.
//   - a proven document is refused (FAIL) when it was recorded for another consumer than the bundle's, when it is for another root than the bundle's, when its path
//     does not compute to the sealed root it names (which includes a document rewritten to name another consumer), and, when a reader is supplied, when L0 does not
//     list that sealed root.
//   - a proven document with no reader (no L0 endpoint) that is internally consistent is a SKIP: the proof holds, but that the node anchored its seal is not confirmed.
//   - with a reader, the leaf is DATED. The covering entry's last canonical height bounds the leaf from above (a leaf cannot be recorded after the anchor that covers it:
//     later is a FAIL); an entry with no window leaves the height undated (SKIP). The lower bound needs the prior anchor: no prior is a SKIP by name, a prior whose
//     consistency proof does not show its tree is a prefix of the covering one is a FAIL, as is a prior whose tree already holds the leaf, one L0 does not list, or a
//     leaf earlier than the prior window's first height. Within both windows it is a PASS.
//   - the version is read BEFORE the status, as the runtime's Check reads it: a version 1 document or a version this verifier does not read is a SKIP whatever its status or
//     its checkpoint says.
//   - an UNAVAILABLE document that carries the node's checkpoint statement is judged by checkCheckpointStatement: a statement whose compact range does not fold to the sealed root
//     it names is a FAIL; a true one is a SKIP (it proves nothing about the bundle) that says so, with L0 confirming the seal when a reader and an anchor are given (a seal L0
//     does not list, or an anchor it cannot read, is a FAIL).
//
// It changes no assurance level: an L0-proven state root is a further integrity check on what the bundle claims, and the level ladder has no state-root rung.
func Check(ctx context.Context, d *Document, bundleRoot [32]byte, consumerID string, reader AnchorReader) Result {
	if d == nil {
		return Result{VerdictSkip, "no state root proof is attached to this bundle: its state root is unchecked (bundles exported before the node kept a root history carry none)"}
	}
	// the version first, as the runtime's Check reads it: a document of a form this verifier does not read is never looked into, whatever its status says
	switch d.Version {
	case DocumentVersion:
	case documentVersionV1:
		return Result{VerdictSkip, "the attached state root proof is version 1, which records no consumer: it shows the root was held but not that this bundle read it, so no consumer recorded, and the bundle's state root is unchecked"}
	default:
		return Result{VerdictSkip, fmt.Sprintf("the attached state root proof is version %q, which this verifier does not read: the bundle's state root is unchecked", d.Version)}
	}
	switch d.Status {
	case StatusAwaitingAnchor:
		return Result{VerdictSkip, fmt.Sprintf("finalized after the newest anchor: the bundle's state root is in the node's history (leaf at canonical height %d, history now %d leaves) but the newest anchored seal covers only %d, so it is unchecked until the next anchor; re-export or re-attach the proof then", d.LeafHeight, d.CurrentSize, d.NewestAnchoredSize)}
	case StatusUnavailable:
		if d.Checkpoint != nil {
			return checkCheckpointStatement(ctx, d, reader)
		}
		return Result{VerdictSkip, "the node could not prove the bundle's state root: " + d.Reason}
	case StatusProven:
	default:
		return Result{VerdictSkip, fmt.Sprintf("the attached state root proof has status %q, which this verifier does not read: the bundle's state root is unchecked", d.Status)}
	}
	if d.Consumer == "" {
		return Result{VerdictSkip, "the attached state root proof names no consumer (no consumer recorded): it cannot be bound to this bundle, so the bundle's state root is unchecked"}
	}
	if consumerID == "" {
		return Result{VerdictSkip, "the bundle names no outcome id, so there is no consumer to bind the proof to: the bundle's state root is unchecked"}
	}
	if d.Consumer != consumerID {
		return Result{VerdictFail, fmt.Sprintf("the leaf was recorded for %q, which is not this bundle's (%q): the proof is for another consumption", d.Consumer, consumerID)}
	}
	if bundleRoot == ([32]byte{}) {
		return Result{VerdictFail, "a state root proof is attached to a bundle that carries no state root"}
	}
	leafRoot, err := decode32(d.StateRoot)
	if err != nil {
		return Result{VerdictFail, "the attached state root proof is malformed: stateRoot: " + err.Error()}
	}
	path, err := decodePath(d.Path)
	if err != nil {
		return Result{VerdictFail, "the attached state root proof is malformed: path" + err.Error()}
	}
	if leafRoot != bundleRoot {
		return Result{VerdictFail, fmt.Sprintf("the proof is for state root %s but the bundle carries %s", d.StateRoot, hex.EncodeToString(bundleRoot[:]))}
	}
	named, err := decode32(d.AccumulatorRoot)
	if err != nil {
		return Result{VerdictFail, "the attached state root proof names a malformed accumulator root: " + err.Error()}
	}
	computed, err := SealedRootOf(d.LeafIndex, d.TreeSize, d.LeafHeight, leafRoot, d.Consumer, path)
	if err != nil || computed != named {
		if err == nil {
			err = ErrBadProof
		}
		return Result{VerdictFail, "the bundle's state root does not prove into the accumulator root the document names (" + d.AccumulatorRoot + "): " + err.Error()}
	}
	if reader == nil {
		return Result{VerdictSkip, fmt.Sprintf("the bundle's state root proves into accumulator root %s (leaf %d of %d, recorded for this bundle), but no L0 endpoint was supplied, so that the node anchored that root is not independently confirmed", short(d.AccumulatorRoot), d.LeafIndex, d.TreeSize)}
	}
	if d.Anchor == nil || d.Anchor.TxHash == "" {
		return Result{VerdictFail, "the attached state root proof names no L0 anchor transaction for its accumulator root"}
	}
	cover, err := reader.AnchorAt(ctx, d.Anchor.TxHash)
	if err != nil {
		return Result{VerdictFail, "could not read the accumulator anchor from L0: " + err.Error()}
	}
	if !cover.Lists(named) {
		return Result{VerdictFail, fmt.Sprintf("the accumulator root %s is not listed in the L0 anchor entry of transaction %s: the node never anchored it", short(d.AccumulatorRoot), short(d.Anchor.TxHash))}
	}
	if !cover.HasWindow() {
		return Result{VerdictSkip, fmt.Sprintf("the bundle's state root is leaf %d of %d in the node's root history and L0 lists its seal, but the covering entry carries no canonical window, so the leaf's height is undated", d.LeafIndex, d.TreeSize)}
	}
	if d.LeafHeight > cover.LastHeight {
		return Result{VerdictFail, fmt.Sprintf("the leaf's canonical height %d is after the last height %d of the anchor batch that covers its seal: a leaf cannot be recorded after the anchor that covers it", d.LeafHeight, cover.LastHeight)}
	}
	p := d.Prior
	if p == nil {
		return Result{VerdictSkip, fmt.Sprintf("the bundle's state root is leaf %d of %d in the node's root history, bound to this bundle, and its seal is listed by L0 with the leaf at or before canonical height %d, but the document names no earlier anchor, so it is unchecked: no earlier anchored window to date it from", d.LeafIndex, d.TreeSize, cover.LastHeight)}
	}
	if p.Anchor == nil || p.Anchor.TxHash == "" {
		return Result{VerdictFail, "the prior anchor names no L0 anchor transaction (prior anchor names no L0 anchor transaction)"}
	}
	priorRoot, err := decode32(p.AccumulatorRoot)
	if err != nil {
		return Result{VerdictFail, "the prior anchor names a malformed accumulator root: " + err.Error()}
	}
	priorMTH, err := decode32(p.MTH)
	if err != nil {
		return Result{VerdictFail, "the prior anchor names a malformed tree hash: " + err.Error()}
	}
	consistency, err := decodePath(p.Consistency)
	if err != nil {
		return Result{VerdictFail, "the prior anchor's consistency proof is malformed: " + err.Error()}
	}
	if seal(p.TreeSize, priorMTH) != priorRoot {
		return Result{VerdictFail, "the prior anchor's tree size and tree hash are not the ones its sealed root commits to: the prior tree is not shown to be a prefix of the covering one"}
	}
	coverMTH, err := VerifyConsistency(p.TreeSize, d.TreeSize, priorMTH, consistency)
	if err != nil || seal(d.TreeSize, coverMTH) != named {
		return Result{VerdictFail, fmt.Sprintf("the prior tree (%d leaves) is not shown to be a prefix of the covering tree (%d leaves): the consistency proof does not verify against the two sealed roots", p.TreeSize, d.TreeSize)}
	}
	if d.LeafIndex < p.TreeSize {
		return Result{VerdictFail, fmt.Sprintf("the leaf (number %d) is inside the prior anchor's tree of %d leaves: it was recorded before the prior anchor, so the prior cannot date it from below", d.LeafIndex, p.TreeSize)}
	}
	prior, err := reader.AnchorAt(ctx, p.Anchor.TxHash)
	if err != nil {
		return Result{VerdictFail, "could not read the prior accumulator anchor from L0: " + err.Error()}
	}
	if !prior.Lists(priorRoot) {
		return Result{VerdictFail, fmt.Sprintf("the prior accumulator root %s is not listed in the L0 anchor entry of transaction %s: the node never anchored it", short(p.AccumulatorRoot), short(p.Anchor.TxHash))}
	}
	if !prior.HasWindow() {
		return Result{VerdictSkip, "the prior anchor's entry carries no canonical window, so there is no earlier anchored window to date it from: the leaf is bounded from above only"}
	}
	if d.LeafHeight < prior.FirstHeight {
		return Result{VerdictFail, fmt.Sprintf("the leaf's canonical height %d is before the first height %d of the prior anchor's window: it is not in the span the two anchors enclose", d.LeafHeight, prior.FirstHeight)}
	}
	return Result{VerdictPass, fmt.Sprintf("the bundle's state root is leaf %d of %d in the node's root history, recorded for this bundle, whose sealed root %s L0 lists in anchor transaction %s; the leaf at canonical height %d lies inside the span [%d, %d] that sealed root and the prior anchor %s (whose tree the covering one extends) enclose", d.LeafIndex, d.TreeSize, short(d.AccumulatorRoot), short(d.Anchor.TxHash), d.LeafHeight, prior.FirstHeight, cover.LastHeight, short(p.Anchor.TxHash))}
}

// checkCheckpointStatement judges the checkpoint an unavailable document states (ledger L1647). The statement proves nothing about the bundle (a skip at best, never a pass): what it
// can be is FALSE, and a false one is a FAIL. Its compact range must fold to the sealed root it names (a range for another tree, or a seal for another size, is refused), and, with an
// L0 endpoint and an anchor named, L0 must list that sealed root (a seal the node never anchored is refused). A statement that holds is a skip saying so: the bundle's root is unchecked,
// and a proof for a bundle recorded before the checkpoint is the document that was exported with it.
func checkCheckpointStatement(ctx context.Context, d *Document, reader AnchorReader) Result {
	c := d.Checkpoint
	if err := c.Verify(); err != nil {
		return Result{VerdictFail, fmt.Sprintf("the node states it checkpointed its root history at leaf %d, and the statement is false: %v", c.Size, err)}
	}
	base := fmt.Sprintf("the node could not prove the bundle's state root: %s; it states its root history was checkpointed at leaf %d (canonical height %d): the checkpoint's compact range folds to sealed root %s, and the bundle's state root is unchecked", d.Reason, c.Size, c.LastHeight, short(c.SealedRoot))
	if reader == nil {
		return Result{VerdictSkip, base + ", but no L0 endpoint was supplied, so that the node anchored that seal is not independently confirmed"}
	}
	if c.Anchor == nil || c.Anchor.TxHash == "" {
		return Result{VerdictSkip, base + ", but the statement names no L0 anchor for that seal, so it is unconfirmed"}
	}
	anchored, err := reader.AnchorAt(ctx, c.Anchor.TxHash)
	if err != nil {
		return Result{VerdictFail, "could not read the checkpoint's anchor from L0: " + err.Error()}
	}
	sealed, _ := decode32(c.SealedRoot)
	if !anchored.Lists(sealed) {
		return Result{VerdictFail, fmt.Sprintf("the checkpoint's sealed root %s is not listed in the L0 anchor entry of transaction %s: the node never anchored it", short(c.SealedRoot), short(c.Anchor.TxHash))}
	}
	return Result{VerdictSkip, base + ", and L0 lists that seal in anchor transaction " + short(c.Anchor.TxHash)}
}
