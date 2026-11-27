// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"fmt"
	"slices"

	"github.com/opendlt/infrix-schema/evidence"
)

// THE ROLE REGISTRY, RECOMPUTED (infrix-core L3112; infrix-schema evidence/role_registry.go). A bundle whose policies read actor::role carries
// a RoleRegistryProof: the registry's sealed root as the leaf of evidence.RoleRegistryAccount in the bundle's StateRoot, and for each actor
// either the actor's own leaf (the roles it holds in the global scope) or the proof that no leaf names it (the adjacent leaves around it at
// consecutive positions, the leaf at an end of the tree, or the empty tree). This verifier recomputes every hash with its own node-tree
// implementation (state_inclusion.go); a proof that does not recompute is a lie and fails the policy re-evaluation.

// VerifyRoleRegistryProof checks p against stateRoot and returns each proven holder's global roles in record form (empty for a holder proven
// to hold none).
func VerifyRoleRegistryProof(stateRoot [32]byte, p *evidence.RoleRegistryProof) (map[string][]string, error) {
	if p == nil {
		return nil, fmt.Errorf("no role registry proof")
	}
	if p.Account.Contract != evidence.RoleRegistryAccount || p.Account.ContractRoot != p.RegistryRoot {
		return nil, fmt.Errorf("the role registry proof's account names %q with root %x, not %s with the registry root %x", p.Account.Contract, p.Account.ContractRoot[:8], evidence.RoleRegistryAccount, p.RegistryRoot[:8])
	}
	if err := VerifyAccountInclusion(stateRoot, &p.Account); err != nil {
		return nil, fmt.Errorf("the role registry root: %w", err)
	}
	leaf := func(l *evidence.RoleRecordLeaf) error {
		if l.Holder == "" || l.Holder != evidence.CanonicalRoleHolder(l.Holder) {
			return fmt.Errorf("a registry leaf names the holder %q, not in canonical form", l.Holder)
		}
		if len(l.Roles) == 0 || !slices.Equal(l.Roles, evidence.CanonicalRoles(l.Roles)) {
			return fmt.Errorf("the registry leaf of %s carries the roles %q, not a non-empty set in record form", l.Holder, l.Roles)
		}
		return VerifyAccountInclusion(p.RegistryRoot, &evidence.AccountInclusionProof{Contract: l.Holder, ContractRoot: evidence.RoleRecordHash(l.Roles),
			Index: l.Index, Leaves: p.Leaves, Siblings: l.Siblings})
	}
	out := make(map[string][]string, len(p.Records))
	for _, rec := range p.Records {
		h := rec.Holder
		if h == "" || h != evidence.CanonicalRoleHolder(h) {
			return nil, fmt.Errorf("a role record names the holder %q, not in canonical form", h)
		}
		if _, dup := out[h]; dup {
			return nil, fmt.Errorf("two role records name %s", h)
		}
		if rec.Held != nil {
			if rec.Before != nil || rec.After != nil || rec.Held.Holder != h {
				return nil, fmt.Errorf("the role record of %s is not one leaf naming it", h)
			}
			if err := leaf(rec.Held); err != nil {
				return nil, fmt.Errorf("the role record of %s: %w", h, err)
			}
			out[h] = append([]string(nil), rec.Held.Roles...)
			continue
		}
		// no leaf names h
		switch {
		case p.Leaves == 0:
			if rec.Before != nil || rec.After != nil || p.RegistryRoot != nodeTreeSeal(0, [32]byte{}) {
				return nil, fmt.Errorf("the role record of %s claims an empty registry the root %x is not", h, p.RegistryRoot[:8])
			}
		case rec.Before == nil && rec.After == nil:
			return nil, fmt.Errorf("the role record of %s proves neither its leaf nor its absence", h)
		default:
			if rec.Before != nil {
				if err := leaf(rec.Before); err != nil {
					return nil, fmt.Errorf("the absence of %s, the leaf before it: %w", h, err)
				}
				if rec.Before.Holder >= h {
					return nil, fmt.Errorf("the absence of %s: the leaf before it names %s, which does not sort before it", h, rec.Before.Holder)
				}
			}
			if rec.After != nil {
				if err := leaf(rec.After); err != nil {
					return nil, fmt.Errorf("the absence of %s, the leaf after it: %w", h, err)
				}
				if rec.After.Holder <= h {
					return nil, fmt.Errorf("the absence of %s: the leaf after it names %s, which does not sort after it", h, rec.After.Holder)
				}
			}
			switch {
			case rec.Before != nil && rec.After != nil && rec.After.Index != rec.Before.Index+1:
				return nil, fmt.Errorf("the absence of %s: the leaves around it are at %d and %d, not adjacent", h, rec.Before.Index, rec.After.Index)
			case rec.Before == nil && rec.After.Index != 0:
				return nil, fmt.Errorf("the absence of %s: no leaf before it, but the leaf after it is at %d, not the first", h, rec.After.Index)
			case rec.After == nil && rec.Before.Index != p.Leaves-1:
				return nil, fmt.Errorf("the absence of %s: no leaf after it, but the leaf before it is at %d of %d, not the last", h, rec.Before.Index, p.Leaves)
			}
		}
		out[h] = []string{}
	}
	return out, nil
}
