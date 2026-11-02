// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package stateroot is the verifier's side of the node's STATE ROOT HISTORY: it decides whether an evidence bundle's state root is a root the node actually held,
// by an inclusion proof into a root-history seal the node anchored to L0.
//
// WHY. A bundle carries the node's state root as of its own finalization. The node anchors its state root only every N canonical blocks (and only when it
// changed), so almost no bundle's root is a root any anchor names, and a verifier that demanded it be the anchored root would refuse nearly every honest bundle. The
// node therefore keeps an append-only Merkle tree of every root it held (one leaf, (canonical height, root), each time its root changed), anchors the sealed root
// of that tree, and an exported bundle carries an inclusion proof of its root's leaf against an anchored seal. A root the node never held is in no anchored seal.
//
// THE TREE is the RFC 9162 Merkle tree: leaf = SHA-256(0x00 || be64(height) || root), node = SHA-256(0x01 || left || right), a node over n leaves splitting at the
// largest power of two below n. The SEALED ROOT the node anchors is SHA-256("infrix-root-history-v1" || be64(n) || treeHash), so what is anchored commits to the
// leaf count as well as the tree.
//
// THIS IMPLEMENTATION IS INDEPENDENT ON PURPOSE. The node builds the tree and makes proofs in the Infrix runtime module (pkg/rootaccum), which this module must not
// import (the verifier isolation fence), so the check is written again here, from the same specification, and the two are pinned by ONE file of vectors the runtime
// repository generates and both repositories' tests read (testdata/state-root-vectors.json): the seal of every tree size to 40, the audit path of every leaf of
// every size, and a table of document cases, a tamper case for every outcome of Check's rule. This package only verifies; it never builds a tree.
package stateroot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// SealDomain is the domain tag of the sealed root.
const SealDomain = "infrix-root-history-v1"

// DocumentVersion identifies the wire form of Document.
const DocumentVersion = "infrix-state-root-proof-v1"

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

// Document is what an export attaches beside a bundle: an inclusion proof of the bundle's state root against an anchored seal, or the reason there is none yet. All
// hashes are lowercase hex.
type Document struct {
	Version   string `json:"version"`
	Status    Status `json:"status"`
	StateRoot string `json:"stateRoot"`
	Reason    string `json:"reason,omitempty"`

	LeafHeight      uint64     `json:"leafHeight,omitempty"`
	LeafIndex       uint64     `json:"leafIndex,omitempty"`
	TreeSize        uint64     `json:"treeSize,omitempty"`
	Path            []string   `json:"path,omitempty"`
	AccumulatorRoot string     `json:"accumulatorRoot,omitempty"`
	Anchor          *AnchorRef `json:"anchor,omitempty"`

	CurrentSize        uint64 `json:"currentSize,omitempty"`
	NewestAnchoredSize uint64 `json:"newestAnchoredSize,omitempty"`
}

// AnchorReader reads what L0 holds. RootsAt returns the roots listed in the anchor entry of the L0 transaction txHash, taken from L0 itself, never from the node that
// produced the bundle. It is the verifier's port, injected by the application like verifykit's L0AnchorConfirmer.
type AnchorReader interface {
	RootsAt(ctx context.Context, txHash string) ([][32]byte, error)
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

// ErrBadProof is returned for a proof that does not prove inclusion.
var ErrBadProof = errors.New("stateroot: the proof does not prove inclusion")

func leafHash(height uint64, root [32]byte) [32]byte {
	var b [41]byte
	b[0] = 0x00
	binary.BigEndian.PutUint64(b[1:9], height)
	copy(b[9:], root[:])
	return sha256.Sum256(b[:])
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
// leaves. It fails for a path of the wrong length for that index and size.
func SealedRootOf(index, size, height uint64, root [32]byte, path [][32]byte) ([32]byte, error) {
	if size == 0 || index >= size {
		return [32]byte{}, ErrBadProof
	}
	fn, sn := index, size-1
	acc := leafHash(height, root)
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

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

// Check is the verifier's judgement of a bundle's state root against an attached document. The rule:
//
//   - no document (every bundle exported before the node kept a root history): SKIP, and the verdict the verifier reached is exactly what it was.
//   - a document that is awaiting an anchor or unavailable: SKIP, with the reason. A bundle finalized after the newest anchor is "unchecked until the next anchor",
//     neither refused nor passed.
//   - a proven document is refused (FAIL) when it is for another root than the bundle's, when its path does not compute to the sealed root it names, and, when a
//     reader is supplied, when L0 does not list that sealed root. A root the node never held is in no anchored seal, so no proof can do all three.
//   - a proven document with no reader (no L0 endpoint) that is internally consistent is a SKIP: the proof holds, but that the node anchored its seal is not confirmed.
//   - a proven document that passes all of it is a PASS.
//
// It changes no assurance level: an L0-proven state root is a further integrity check on what the bundle claims, and the level ladder has no state-root rung.
func Check(ctx context.Context, d *Document, bundleRoot [32]byte, reader AnchorReader) Result {
	if d == nil {
		return Result{VerdictSkip, "no state root proof is attached to this bundle: its state root is unchecked (bundles exported before the node kept a root history carry none)"}
	}
	if d.Version != DocumentVersion {
		return Result{VerdictSkip, fmt.Sprintf("the attached state root proof is version %q, which this verifier does not read: the bundle's state root is unchecked", d.Version)}
	}
	switch d.Status {
	case StatusAwaitingAnchor:
		return Result{VerdictSkip, fmt.Sprintf("finalized after the newest anchor: the bundle's state root is in the node's history (leaf at canonical height %d, history now %d leaves) but the newest anchored seal covers only %d, so it is unchecked until the next anchor; re-export or re-attach the proof then", d.LeafHeight, d.CurrentSize, d.NewestAnchoredSize)}
	case StatusUnavailable:
		return Result{VerdictSkip, "the node could not prove the bundle's state root: " + d.Reason}
	case StatusProven:
	default:
		return Result{VerdictSkip, fmt.Sprintf("the attached state root proof has status %q, which this verifier does not read: the bundle's state root is unchecked", d.Status)}
	}
	if bundleRoot == ([32]byte{}) {
		return Result{VerdictFail, "a state root proof is attached to a bundle that carries no state root"}
	}
	leafRoot, err := decode32(d.StateRoot)
	if err != nil {
		return Result{VerdictFail, "the attached state root proof is malformed: stateRoot: " + err.Error()}
	}
	path := make([][32]byte, len(d.Path))
	for i, s := range d.Path {
		if path[i], err = decode32(s); err != nil {
			return Result{VerdictFail, fmt.Sprintf("the attached state root proof is malformed: path[%d]: %v", i, err)}
		}
	}
	if leafRoot != bundleRoot {
		return Result{VerdictFail, fmt.Sprintf("the proof is for state root %s but the bundle carries %s", d.StateRoot, hex.EncodeToString(bundleRoot[:]))}
	}
	named, err := decode32(d.AccumulatorRoot)
	if err != nil {
		return Result{VerdictFail, "the attached state root proof names a malformed accumulator root: " + err.Error()}
	}
	computed, err := SealedRootOf(d.LeafIndex, d.TreeSize, d.LeafHeight, leafRoot, path)
	if err != nil || computed != named {
		if err == nil {
			err = ErrBadProof
		}
		return Result{VerdictFail, "the bundle's state root does not prove into the accumulator root the document names (" + d.AccumulatorRoot + "): " + err.Error()}
	}
	if reader == nil {
		return Result{VerdictSkip, fmt.Sprintf("the bundle's state root proves into accumulator root %s (leaf %d of %d), but no L0 endpoint was supplied, so that the node anchored that root is not independently confirmed", short(d.AccumulatorRoot), d.LeafIndex, d.TreeSize)}
	}
	if d.Anchor == nil || d.Anchor.TxHash == "" {
		return Result{VerdictFail, "the attached state root proof names no L0 anchor transaction for its accumulator root"}
	}
	listed, err := reader.RootsAt(ctx, d.Anchor.TxHash)
	if err != nil {
		return Result{VerdictFail, "could not read the accumulator anchor from L0: " + err.Error()}
	}
	for _, r := range listed {
		if r == named {
			return Result{VerdictPass, fmt.Sprintf("the bundle's state root is leaf %d of %d in the node's root history, whose sealed root %s L0 lists in anchor transaction %s", d.LeafIndex, d.TreeSize, short(d.AccumulatorRoot), short(d.Anchor.TxHash))}
		}
	}
	return Result{VerdictFail, fmt.Sprintf("the accumulator root %s is not listed in the L0 anchor entry of transaction %s: the node never anchored it", short(d.AccumulatorRoot), short(d.Anchor.TxHash))}
}
