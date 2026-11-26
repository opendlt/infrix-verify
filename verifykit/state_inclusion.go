// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/opendlt/infrix-schema/evidence"
)

// THE STATE PROOFS, RECOMPUTED (brief 28bd phase 2b, L2992; the native proof plan's L1 and L2).
//
// This is the verifier's own implementation of the node state tree's hashing (infrix-core pkg/noderoot), written from its specification and
// held to the node's implementation by a differential test in core, so the verifier trusts no node code:
//
//	contract leaf(key, value) = H("infrix:state-leaf:v2" || be64(len key) || key || be64(len value) || value)
//	contract node(a, b)       = H("infrix:state-node:v2" || min(a,b) || max(a,b))
//	node-tree leaf(url, root) = H(0x00 || be32(len url) || url || root)
//	node-tree node(l, r)      = H(0x01 || l || r)        (an odd last node is carried up unchanged)
//	sealed root               = H(be32(len d) || d || be64(leaves) || tree), d = "infrix-node-state-root-v2"

func stateLeafHash(key string, value []byte) [32]byte {
	var n [8]byte
	h := sha256.New()
	h.Write([]byte("infrix:state-leaf:v2"))
	binary.BigEndian.PutUint64(n[:], uint64(len(key)))
	h.Write(n[:])
	h.Write([]byte(key))
	binary.BigEndian.PutUint64(n[:], uint64(len(value)))
	h.Write(n[:])
	h.Write(value)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func stateNodeHash(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	h := sha256.New()
	h.Write([]byte("infrix:state-node:v2"))
	h.Write(a[:])
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeTreeLeafHash(url string, root [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(url)))
	h.Write(l[:])
	h.Write([]byte(url))
	h.Write(root[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeTreeNodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeTreeSeal(leaves uint64, tree [32]byte) [32]byte {
	const d = "infrix-node-state-root-v2"
	h := sha256.New()
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(d)))
	h.Write(l[:])
	h.Write([]byte(d))
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], leaves)
	h.Write(c[:])
	h.Write(tree[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// maxStateProofDepth bounds a key path: a contract tree of 2^64 leaves is 64 levels deep, so a longer path is not a path.
const maxStateProofDepth = 64

// VerifyStorageInclusion checks that p.Key holds p.Value in the contract state whose root is p.ContractRoot (L1).
func VerifyStorageInclusion(p *evidence.StorageInclusionProof) error {
	if p == nil {
		return fmt.Errorf("no storage inclusion proof")
	}
	if p.Contract == "" || p.Key == "" {
		return fmt.Errorf("a storage inclusion proof names no contract or key")
	}
	if len(p.KeyPath) > maxStateProofDepth {
		return fmt.Errorf("key %q of %s: a %d-node path is deeper than any contract tree", p.Key, p.Contract, len(p.KeyPath))
	}
	h := stateLeafHash(p.Key, p.Value)
	for _, sib := range p.KeyPath {
		h = stateNodeHash(h, sib)
	}
	if h != p.ContractRoot {
		return fmt.Errorf("key %q of %s does not fold to the contract root it names", p.Key, p.Contract)
	}
	return nil
}

// VerifyAccountInclusion checks that p.ContractRoot is p.Contract's leaf in the sealed node state root stateRoot (L2).
func VerifyAccountInclusion(stateRoot [32]byte, p *evidence.AccountInclusionProof) error {
	if p == nil {
		return fmt.Errorf("no account inclusion proof")
	}
	if p.Contract == "" || p.Leaves == 0 || p.Index >= p.Leaves {
		return fmt.Errorf("account inclusion of %q names leaf %d of %d", p.Contract, p.Index, p.Leaves)
	}
	h := nodeTreeLeafHash(p.Contract, p.ContractRoot)
	idx, size, used := p.Index, p.Leaves, 0
	for size > 1 {
		if idx%2 == 1 {
			if used >= len(p.Siblings) {
				return fmt.Errorf("account inclusion of %s: too few siblings", p.Contract)
			}
			h = nodeTreeNodeHash(p.Siblings[used], h)
			used++
		} else if idx+1 < size {
			if used >= len(p.Siblings) {
				return fmt.Errorf("account inclusion of %s: too few siblings", p.Contract)
			}
			h = nodeTreeNodeHash(h, p.Siblings[used])
			used++
		}
		idx /= 2
		size = (size + 1) / 2
	}
	if used != len(p.Siblings) {
		return fmt.Errorf("account inclusion of %s: %d sibling(s) unused", p.Contract, len(p.Siblings)-used)
	}
	if nodeTreeSeal(p.Leaves, h) != stateRoot {
		return fmt.Errorf("the contract root of %s is not its leaf in the bundle's state root", p.Contract)
	}
	return nil
}

// stateVerdict is what the bundle's state proofs establish: storage (L1) when the bundle claims at least one key and every storage proof
// verifies; account (L2) when, in addition, every claimed key's contract root is proven to be that contract's leaf in the bundle's StateRoot.
type stateVerdict struct {
	Storage, Account bool
	Failure          string
}

func checkStateProofs(bundle *evidence.EvidenceBundle) stateVerdict {
	if len(bundle.StorageProofs) == 0 && len(bundle.AccountProofs) == 0 {
		return stateVerdict{}
	}
	if len(bundle.StorageProofs) == 0 {
		return stateVerdict{Failure: "the bundle carries account inclusions but claims no storage key"}
	}
	for i := range bundle.StorageProofs {
		if err := VerifyStorageInclusion(&bundle.StorageProofs[i]); err != nil {
			return stateVerdict{Failure: err.Error()}
		}
	}
	accounts := make(map[string]*evidence.AccountInclusionProof, len(bundle.AccountProofs))
	for i := range bundle.AccountProofs {
		a := &bundle.AccountProofs[i]
		if err := VerifyAccountInclusion(bundle.StateRoot, a); err != nil {
			return stateVerdict{Storage: true, Failure: err.Error()}
		}
		if prev, dup := accounts[a.Contract]; dup && prev.ContractRoot != a.ContractRoot {
			return stateVerdict{Storage: true, Failure: fmt.Sprintf("two account inclusions give %s different roots", a.Contract)}
		}
		accounts[a.Contract] = a
	}
	for _, sp := range bundle.StorageProofs {
		a, ok := accounts[sp.Contract]
		if !ok {
			// the key is proven in a contract root that nothing ties to the state root: L1, not L2
			return stateVerdict{Storage: true}
		}
		if a.ContractRoot != sp.ContractRoot {
			return stateVerdict{Storage: true, Failure: fmt.Sprintf("key %q is proven in a root of %s that is not the root the state root holds for it", sp.Key, sp.Contract)}
		}
	}
	return stateVerdict{Storage: true, Account: true}
}
