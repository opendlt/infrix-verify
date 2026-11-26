// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// LocalEmbeddedNetwork is the network of a local run's own in-process Accumulate network: a level verified under its pin is labelled
// local-embedded, never Kermit, never mainnet.
const LocalEmbeddedNetwork = "local-embedded"

// LocalEmbeddedPin is a local run's pin file (pin.local-embedded.json, written next to its bundle, never in it): the embedded network's pin and
// the governance account and page a relying party names for G2. A relying party passes it explicitly (the CLI's --l0-pin, an agent's l0Pin,
// a browser client's pin field); a verifier never reads it from the bundle. This is the ONE parser every client runs (brief 28bs row 2:
// the CLI, the agent API and the playground worker), so each refuses the same malformed pin.
type LocalEmbeddedPin struct {
	Pin               consensus.Pin `json:"pin"`
	GovernanceAccount string        `json:"governanceAccount"`
	GovernancePage    string        `json:"governancePage"`
}

// ParseLocalEmbeddedPin parses a local run's pin. It refuses an unknown field, trailing data, a network other than local-embedded, a pin that
// names no chain or no validators, and a pin with no governance account or page.
func ParseLocalEmbeddedPin(data []byte) (*LocalEmbeddedPin, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p LocalEmbeddedPin
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse the local-embedded pin: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse the local-embedded pin: trailing data after the pin")
	}
	switch {
	case p.Pin.Network != LocalEmbeddedNetwork:
		return nil, fmt.Errorf("the pin is for network %q; a local run's pin is for %q (Kermit's pin is compiled into the verifier)", p.Pin.Network, LocalEmbeddedNetwork)
	case p.Pin.ChainID == "" || len(p.Pin.Validators.Validators) == 0:
		return nil, fmt.Errorf("the local-embedded pin names no chain or no validators")
	case p.GovernanceAccount == "" || p.GovernancePage == "":
		return nil, fmt.Errorf("the local-embedded pin names no governance account or page")
	}
	return &p, nil
}

// Apply sets the relying party's trust root on a verification: the pin, and the governance account and page G2 is held to.
func (p *LocalEmbeddedPin) Apply(o *Options) {
	o.L0Pin, o.GovernanceAccount, o.GovernancePage = &p.Pin, p.GovernanceAccount, p.GovernancePage
}
