// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
)

// NetworkKermit is the Accumulate Kermit testnet. It is the only network with a compiled pin: verification never runs against mainnet.
const NetworkKermit = "kermit"

// kermitPin is the current incarnation of Kermit's Directory, read from its genesis (CometBFT RPC /genesis on the Directory, port 16592) on 2026-11-26:
// chain DevNet.Directory, genesis 2026-02-01T01:44:46Z, initial height 2, three validators of power 1. The capture command is recorded in
// testdata/kermit/capture.json. A reset of Kermit is a new incarnation: it gets a new pin here, and the old pin is kept in kermitPreviousPins so a relying
// party can still verify an old proof by selecting it explicitly.
var kermitPin = consensus.Pin{
	Network:       NetworkKermit,
	ChainID:       "DevNet.Directory",
	InitialHeight: 2,
	GenesisTime:   consensus.Timestamp{Seconds: 1769910286},
	Validators: consensus.ValidatorSet{Validators: []consensus.Validator{
		{PubKey: mustHex("40e6e8b96de7e7ed4c38815448abe22ab555236418d813b3a02cb6a7bc42871b"), VotingPower: 1}, // 309068791543793065C5A36C15BBCFA5259C707D
		{PubKey: mustHex("625b03bfad7d82b11d69be478954ca6293468694f7868a8dfe64d0923a81b262"), VotingPower: 1}, // 3184B7252EA7C152E7398A255B5423FD825F1199
		{PubKey: mustHex("0f9f714a43c0c33731f6e097aea9567f8d0b8817b86510d888e333c84d0b8191"), VotingPower: 1}, // 364D06669499526150676CBD922DADCCD4E01553
	}},
}

// kermitPreviousPins are Kermit incarnations before the current one. None is recorded: the 2026-02-01 genesis is the first incarnation Infrix pins.
var kermitPreviousPins []consensus.Pin

func mustHex(s string) Bytes {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// CompiledPin returns a copy of the pin compiled in for a network. Only Kermit has one.
func CompiledPin(network string) (consensus.Pin, error) {
	switch network {
	case NetworkKermit:
		return clonePin(&kermitPin), nil
	case "":
		return consensus.Pin{}, errors.New("no network named: the verifier must say which network's pin to use")
	default:
		return consensus.Pin{}, fmt.Errorf("no pin is compiled in for network %q; only %q has one, and any other trust root must be supplied explicitly", network, NetworkKermit)
	}
}

// PreviousPins returns copies of a network's earlier incarnations, for a relying party that must verify an old proof and passes one explicitly.
func PreviousPins(network string) []consensus.Pin {
	if network != NetworkKermit {
		return nil
	}
	out := make([]consensus.Pin, len(kermitPreviousPins))
	for i := range kermitPreviousPins {
		out[i] = clonePin(&kermitPreviousPins[i])
	}
	return out
}

func clonePin(p *consensus.Pin) consensus.Pin {
	q := *p
	q.Validators.Validators = make([]consensus.Validator, len(p.Validators.Validators))
	for i, v := range p.Validators.Validators {
		q.Validators.Validators[i] = consensus.Validator{PubKey: append(Bytes(nil), v.PubKey...), VotingPower: v.VotingPower}
	}
	return q
}

// selectPin is the only place a pin is chosen: the explicit override when the relying party passed one, otherwise the compiled pin for the named network.
func selectPin(opts Options) (*consensus.Pin, bool, error) {
	if opts.OverridePin != nil {
		p := clonePin(opts.OverridePin)
		return &p, true, nil
	}
	p, err := CompiledPin(opts.Network)
	if err != nil {
		return nil, false, err
	}
	return &p, false, nil
}
