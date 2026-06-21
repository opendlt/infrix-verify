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
	forbidden := []string{
		"github.com/AccumulateNetwork/infrix/pkg/l0",
		"github.com/AccumulateNetwork/infrix/pkg/production",
		"github.com/AccumulateNetwork/infrix/pkg/devnet",
	}

	out, err := exec.Command("go", "list", "-deps", "github.com/AccumulateNetwork/infrix/pkg/verifykit").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps pkg/verifykit failed: %v\n%s", err, out)
	}
	deps := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		deps[strings.TrimSpace(line)] = struct{}{}
	}
	for _, f := range forbidden {
		if _, ok := deps[f]; ok {
			t.Errorf("pkg/verifykit transitively imports %s — the verifier core must stay free "+
				"of the live node. L0 confirmation belongs behind the L0AnchorConfirmer port "+
				"(the NativeL0Confirmer adapter lives in pkg/verifykit/l0native and is injected by "+
				"the application). Move whatever pulled %s out of the core. (docs/extraction-plan M4.2)",
				f, f)
		}
	}
}
