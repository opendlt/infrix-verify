// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Pin is a trust root the VERIFIER holds: one incarnation of a Directory chain, named by its genesis. A proof never supplies it. The pin trusts its genesis
// validator set to sign the chain's first height; every later set is reached from it by verified steps.
type Pin struct {
	Network       string       `json:"network"`       // what the pin is for, e.g. "kermit" or "simulator"; never mainnet
	ChainID       string       `json:"chainId"`       // the Directory's CometBFT chain id
	InitialHeight int64        `json:"initialHeight"` // the genesis initial height
	GenesisTime   Timestamp    `json:"genesisTime"`   // the genesis time
	Validators    ValidatorSet `json:"validators"`    // the genesis validator set, in canonical order
}

// pinDomain separates a pin's identity hash from every other hash.
const pinDomain = "infrix-l0proof-pin/v1"

// ID is the incarnation identity: "pin:" and the hex SHA-256 of the pin's every field, length-prefixed under a domain tag. A new incarnation (a reset
// network) has a new genesis and so a new ID, and a proof names the ID it was captured under.
func (p *Pin) ID() string {
	var b []byte
	str := func(s string) {
		b = binary.AppendUvarint(b, uint64(len(s)))
		b = append(b, s...)
	}
	str(pinDomain)
	str(p.Network)
	str(p.ChainID)
	b = binary.AppendVarint(b, p.InitialHeight)
	b = binary.AppendVarint(b, p.GenesisTime.Seconds)
	b = binary.AppendVarint(b, int64(p.GenesisTime.Nanos))
	b = binary.AppendUvarint(b, uint64(len(p.Validators.Validators)))
	for _, v := range p.Validators.Validators {
		str(string(v.PubKey))
		b = binary.AppendVarint(b, v.VotingPower)
	}
	h := sha256.Sum256(b)
	return "pin:" + hex.EncodeToString(h[:])
}
