// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/opendlt/infrix-schema/evidence"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// JSONOptions are the offline options a JSON caller (the WASM build in @infrix/client, the CLI) passes: the trust root and the relying party's
// governance page. Nothing here is read from the bundle.
type JSONOptions struct {
	L0Network         string         `json:"l0Network,omitempty"`
	L0Pin             *consensus.Pin `json:"l0Pin,omitempty"`
	GovernanceAccount string         `json:"governanceAccount,omitempty"`
	GovernancePage    string         `json:"governancePage,omitempty"`
	Require           string         `json:"require,omitempty"`
}

// VerifyJSON is the ONE verifier body every surface calls (native plan phase 8): it decodes a portable package and offline options, runs Verify, and
// returns the report's JSON. The WASM build (infrix-verify/wasm) exports exactly this, so the TypeScript SDK has no second implementation that can drift.
func VerifyJSON(pkgJSON, optsJSON []byte) ([]byte, error) {
	var pkg evidence.PortableEvidencePackage
	if err := json.Unmarshal(pkgJSON, &pkg); err != nil {
		return nil, fmt.Errorf("decode the package: %w", err)
	}
	var o JSONOptions
	if len(optsJSON) > 0 {
		if err := json.Unmarshal(optsJSON, &o); err != nil {
			return nil, fmt.Errorf("decode the options: %w", err)
		}
	}
	opts := Options{L0Network: o.L0Network, L0Pin: o.L0Pin, GovernanceAccount: o.GovernanceAccount, GovernancePage: o.GovernancePage}
	if o.Require != "" {
		req, err := ParseRequiredLevel(o.Require)
		if err != nil {
			return nil, err
		}
		opts.Require = req
	}
	return json.Marshal(Verify(context.Background(), &pkg, opts))
}
