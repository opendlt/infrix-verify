// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"errors"
	"fmt"
)

// accountTypeKeyPage is protocol.AccountTypeKeyPage.
const accountTypeKeyPage = 9

// emptyObject is encoding.EmptyObject: what Accumulate writes for a value with every field empty.
const emptyObject = 0x80

// KeyPage is a key page's main state as the verifier reads it from the exact bytes an AccountProof commits (protocol.KeyPage, protocol/types_gen.go): the
// thresholds and keys a governance check computes from. Read it only from an AccountProof whose State has been verified, so the bytes are the page's.
type KeyPage struct {
	URL                  string
	CreditBalance        uint64
	AcceptThreshold      uint64
	RejectThreshold      uint64
	ResponseThreshold    uint64
	BlockThreshold       uint64
	Version              uint64
	Keys                 []KeySpec
	TransactionBlacklist *uint64
}

// KeySpec is protocol.KeySpec.
type KeySpec struct {
	PublicKeyHash []byte
	LastUsedOn    uint64
	Delegate      string
}

// DecodeKeyPage reads a key page's main state. Fields are read in the order Accumulate writes them (KeyPage.MarshalBinary), with keys repeated as field 9;
// any other field, an out-of-order field, a padded varint or trailing bytes is refused.
func DecodeKeyPage(main []byte) (*KeyPage, error) {
	typ, url, err := decodeAccountHeader(main)
	if err != nil {
		return nil, err
	}
	if typ != accountTypeKeyPage {
		return nil, fmt.Errorf("the account is type %d, not a key page", typ)
	}
	kp := &KeyPage{URL: url}
	r := &reader{b: main}
	// skip the header decodeAccountHeader already read
	if _, err := r.uvarint("field"); err != nil {
		return nil, err
	}
	if _, err := r.uvarint("type"); err != nil {
		return nil, err
	}
	if _, err := r.uvarint("field"); err != nil {
		return nil, err
	}
	if _, err := r.str("url"); err != nil {
		return nil, err
	}
	last := uint64(2)
	for !r.done() {
		f, err := r.uvarint("key page field")
		if err != nil {
			return nil, err
		}
		if f < last || (f == last && f != 9) {
			return nil, fmt.Errorf("key page field %d is out of order", f)
		}
		last = f
		switch f {
		case 3, 4, 5, 6, 7, 8:
			v, err := r.uvarint("key page field")
			if err != nil {
				return nil, err
			}
			*[]*uint64{nil, nil, nil, &kp.CreditBalance, &kp.AcceptThreshold, &kp.RejectThreshold, &kp.ResponseThreshold, &kp.BlockThreshold, &kp.Version}[f] = v
		case 9:
			raw, err := r.str("key spec")
			if err != nil {
				return nil, err
			}
			ks, err := decodeKeySpec([]byte(raw))
			if err != nil {
				return nil, fmt.Errorf("key %d: %w", len(kp.Keys), err)
			}
			kp.Keys = append(kp.Keys, *ks)
		case 10:
			v, err := r.uvarint("transaction blacklist")
			if err != nil {
				return nil, err
			}
			kp.TransactionBlacklist = &v
		default:
			return nil, fmt.Errorf("the key page has unknown field %d", f)
		}
	}
	return kp, nil
}

func decodeKeySpec(b []byte) (*KeySpec, error) {
	ks := new(KeySpec)
	if len(b) == 1 && b[0] == emptyObject {
		return ks, nil
	}
	r := &reader{b: b}
	last := uint64(0)
	for !r.done() {
		f, err := r.uvarint("key spec field")
		if err != nil {
			return nil, err
		}
		if f <= last {
			return nil, fmt.Errorf("key spec field %d is out of order or repeated", f)
		}
		last = f
		switch f {
		case 1:
			s, err := r.str("public key hash")
			if err != nil {
				return nil, err
			}
			ks.PublicKeyHash = []byte(s)
		case 2:
			if ks.LastUsedOn, err = r.uvarint("last used on"); err != nil {
				return nil, err
			}
		case 3:
			if ks.Delegate, err = r.str("delegate"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the key spec has unknown field %d", f)
		}
	}
	if len(b) == 0 {
		return nil, errors.New("an empty key spec encoding")
	}
	return ks, nil
}
