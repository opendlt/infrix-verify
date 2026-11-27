// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof_test

import (
	"os/exec"
	"strings"
	"testing"
)

// l0proofSelf is the package tree the verifier is allowed to import besides the standard library.
const l0proofSelf = "github.com/opendlt/infrix-verify/l0proof"

// foreignDeps returns the dependencies in a `go list -deps` output that are neither the standard library (no dot in the first path element) nor l0proof
// itself. Accumulate, CometBFT and any certen package all land here.
func foreignDeps(deps string) []string {
	var out []string
	for _, line := range strings.Split(deps, "\n") {
		d := strings.TrimSpace(line)
		if d == "" || d == l0proofSelf || strings.HasPrefix(d, l0proofSelf+"/") {
			continue
		}
		first, _, _ := strings.Cut(d, "/")
		if strings.Contains(first, ".") || strings.Contains(strings.ToLower(d), "certen") {
			out = append(out, d)
		}
	}
	return out
}

// l0proof depends on the standard library (with its crypto) only: Accumulate and CometBFT enter solely through the separate, test-only l0proofref module,
// and no certen package may enter at all (L2993).
func TestL0ProofDependsOnTheStandardLibraryOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", l0proofSelf+"/...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	if bad := foreignDeps(string(out)); len(bad) > 0 {
		t.Fatalf("l0proof imports packages outside the standard library: %s", strings.Join(bad, ", "))
	}
}

// The fence has teeth: Accumulate, CometBFT, a certen package and a module path are flagged; the standard library and l0proof are not.
func TestTheL0ProofFenceBitesAForeignImport(t *testing.T) {
	ok := "crypto/ed25519\nencoding/json\n" + l0proofSelf + "\n" + l0proofSelf + "/consensus\n"
	if bad := foreignDeps(ok); len(bad) != 0 {
		t.Fatalf("flagged %v", bad)
	}
	for _, d := range []string{"gitlab.com/accumulatenetwork/accumulate/protocol", "github.com/cometbft/cometbft/types", "certen/proof", "github.com/opendlt/infrix-schema/evidence"} {
		if bad := foreignDeps(ok + d + "\n"); len(bad) != 1 || bad[0] != d {
			t.Fatalf("did not flag %s: %v", d, bad)
		}
	}
}
