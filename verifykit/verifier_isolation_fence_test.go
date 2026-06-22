// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVerifierCoreHasNoRuntimeNodeDependency is the Tier-1 verifier-isolation
// fence (docs/extraction-plan, M4.2): the verifier CORE — pkg/verifykit — must
// be able to verify a portable proof with ZERO trust in (and zero compile-time
// dependency on) the live Accumulate node. Concretely its transitive
// dependency graph MUST NOT contain the live L0 client (pkg/l0), the
// composition root (pkg/production), or the test-network harness (pkg/devnet).
//
// The L0 confirmation the verifier needs for L4 is taken through the
// L0AnchorConfirmer PORT (anchor_confirmer.go); the live-node ADAPTER
// (NativeL0Confirmer) lives in pkg/verifykit/l0native and is injected by the
// application, never imported by the core. Re-introducing any import that
// transitively reaches one of the forbidden packages fails RED here — this is
// what keeps "verify without trusting the node" structurally provable rather
// than aspirational.
//
// Transitive check (`go list -deps`), so a leak through ANY new intermediate
// import is caught, not just a direct import.
func TestVerifierCoreHasNoRuntimeNodeDependency(t *testing.T) {
	const corePrefix = "github.com/AccumulateNetwork/infrix/pkg/"

	// Allowlist (not a forbidden-list): the verifier core may import ONLY these
	// main-module packages. Everything else verification-side now lives in the
	// infrix-schema module (evidence wire format + assurance ladder) or is
	// injected through a port (l0native adapter). M4.2 dropped pkg/l0; the M4.3
	// schema repoint then collapsed verifykit's main-module surface from ~18
	// runtime packages (anchor, governance, objects, state, workflow, evidence,
	// assurance, zkp, ...) down to this set. Any new main-module import that is
	// not on the allowlist fails RED — that is the boundary that keeps the
	// verifier independently extractable and provably node-free.
	allowed := map[string]bool{
		// witness is the independent-attestation interface set; it imports no
		// other Infrix package. It is the last main-module dep and is slated to
		// move into the verifier module / a schema leaf.
		"github.com/AccumulateNetwork/infrix-verify/witness": true,
	}

	out, err := exec.Command("go", "list", "-deps", "github.com/AccumulateNetwork/infrix/pkg/verifykit").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps pkg/verifykit failed: %v\n%s", err, out)
	}
	var leaks []string
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" || dep == "github.com/AccumulateNetwork/infrix/pkg/verifykit" {
			continue
		}
		if strings.HasPrefix(dep, corePrefix) && !allowed[dep] {
			leaks = append(leaks, dep)
		}
	}
	if len(leaks) > 0 {
		t.Errorf("the verifier core (pkg/verifykit) transitively imports %d disallowed main-module "+
			"package(s): %s\nThe verifier must depend only on the infrix-schema module, crypto, the "+
			"witness interface, and ports (L0 confirmation is injected via the l0native adapter). "+
			"Move whatever pulled these into infrix-schema or behind a port. (docs/extraction-plan M4.2/M4.3)",
			len(leaks), strings.Join(leaks, ", "))
	}
}
