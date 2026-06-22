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
// fence (docs/extraction-plan, M4): the verifier CORE — verifykit, now in the
// standalone infrix-verify module — must be able to verify a portable proof
// with ZERO trust in (and zero compile-time dependency on) the live Accumulate
// node. Concretely its transitive dependency graph MUST NOT contain ANY package
// from the main Infrix runtime module (github.com/AccumulateNetwork/infrix/...)
// — that includes the live L0 client (pkg/l0), the composition root
// (pkg/production), the test-network harness (pkg/devnet), and the runtime
// evidence/governance packages.
//
// The L0 confirmation the verifier needs for L4 is taken through the
// L0AnchorConfirmer PORT (anchor_confirmer.go); the live-node ADAPTER
// (NativeL0Confirmer) lives in the main module (pkg/verifyl0native) and is
// injected by the application, never imported by the core.
//
// After M4 the verifier consumes only the published infrix-schema contract
// module, the in-module witness leaf, crypto, and the Go standard library, so
// the allowlist is EMPTY: any dependency on the main runtime module fails RED.
// The check is transitive (`go list -deps`), so a leak through ANY new
// intermediate import is caught — and it fires even in workspace mode, where a
// stray main-module import would otherwise resolve and silently compile.
func TestVerifierCoreHasNoRuntimeNodeDependency(t *testing.T) {
	// Any dependency under the MAIN runtime module is forbidden. The trailing
	// slash keeps this from matching the verifier's own module
	// (github.com/opendlt/infrix-verify/...), which is allowed.
	const runtimeModulePrefix = "github.com/AccumulateNetwork/infrix/"

	// Empty allowlist: the verifier core may import ZERO packages from the main
	// runtime module. Everything it needs lives in infrix-schema (evidence wire
	// format + assurance ladder), the in-module witness leaf, or behind a port.
	allowed := map[string]bool{}

	out, err := exec.Command("go", "list", "-deps", "github.com/opendlt/infrix-verify/verifykit").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps infrix-verify/verifykit failed: %v\n%s", err, out)
	}
	var leaks []string
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" {
			continue
		}
		if strings.HasPrefix(dep, runtimeModulePrefix) && !allowed[dep] {
			leaks = append(leaks, dep)
		}
	}
	if len(leaks) > 0 {
		t.Errorf("the verifier core (infrix-verify/verifykit) transitively imports %d package(s) from "+
			"the main runtime module: %s\nThe verifier must depend only on the published infrix-schema "+
			"module, the in-module witness leaf, crypto, and ports (L0 confirmation is injected via the "+
			"pkg/verifyl0native adapter in the main module). Move whatever pulled these into infrix-schema "+
			"or behind a port. (docs/extraction-plan M4)",
			len(leaks), strings.Join(leaks, ", "))
	}
}
