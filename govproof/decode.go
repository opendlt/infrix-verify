// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package govproof

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The Accumulate binary encodings this package reads (pkg/types/encoding writer.go, the operator's fork gitlab.com/Jason_Gregoire/accumulate): a field is
// its number as a uvarint, then its value; an enum, uint or bool is a uvarint; a time is a signed varint of Unix seconds; a string, URL or byte string is
// a uvarint length and the bytes; a hash (WriteHash) is exactly 32 raw bytes; a nested value (WriteValue) is a uvarint length and its own encoding. Empty
// fields are omitted and fields appear in ascending order. Every hash is taken over the exact bytes carried, so a re-encoding can never stand in for them.

// Accumulate protocol enum values (protocol/enums_gen.go).
const (
	accountTypeSystemLedger = 14
	signatureTypeED25519    = 2
	voteTypeAccept          = 0
)

// maxKeys bounds the keys of one page (Accumulate's globals.limits.pageEntries is 256).
const maxKeys = 256

type reader struct {
	b   []byte
	off int
}

func (r *reader) done() bool { return r.off == len(r.b) }

func (r *reader) uvarint(what string) (uint64, error) {
	v, n := binary.Uvarint(r.b[r.off:])
	if n <= 0 || n != len(binary.AppendUvarint(nil, v)) {
		return 0, fmt.Errorf("%s: malformed or padded varint at byte %d", what, r.off)
	}
	r.off += n
	return v, nil
}

func (r *reader) varint(what string) (int64, error) {
	v, n := binary.Varint(r.b[r.off:])
	if n <= 0 || n != len(binary.AppendVarint(nil, v)) {
		return 0, fmt.Errorf("%s: malformed or padded varint at byte %d", what, r.off)
	}
	r.off += n
	return v, nil
}

func (r *reader) raw(n uint64, what string) ([]byte, error) {
	if n > uint64(len(r.b)-r.off) {
		return nil, fmt.Errorf("%s: %d bytes overrun the encoding", what, n)
	}
	b := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return b, nil
}

func (r *reader) bytes(what string) ([]byte, error) {
	n, err := r.uvarint(what)
	if err != nil {
		return nil, err
	}
	return r.raw(n, what)
}

// next consumes the next field number, which must be above prev (fields are written once each, in ascending order) and is returned.
func (r *reader) next(prev uint64, what string) (uint64, error) {
	f, err := r.uvarint(what)
	if err != nil {
		return 0, err
	}
	if f <= prev {
		return 0, fmt.Errorf("%s: field %d follows field %d; fields are written once, in ascending order", what, f, prev)
	}
	return f, nil
}

// systemLedger is what a partition's system ledger establishes (protocol.SystemLedger: 1 type, 2 url, 3 index, 4 timestamp, ...). Only the first four are
// read; the rest of the encoding is hashed, never interpreted.
type systemLedger struct {
	URL   string
	Index uint64
	Time  int64
}

func decodeSystemLedger(main []byte) (*systemLedger, error) {
	r := &reader{b: main}
	l := &systemLedger{}
	f, err := r.next(0, "system ledger")
	if err != nil {
		return nil, err
	}
	if f != 1 {
		return nil, fmt.Errorf("system ledger: field %d where the type is required", f)
	}
	t, err := r.uvarint("system ledger type")
	if err != nil {
		return nil, err
	}
	if t != accountTypeSystemLedger {
		return nil, fmt.Errorf("the account is type %d, not a system ledger (%d)", t, accountTypeSystemLedger)
	}
	prev := uint64(1)
	for !r.done() {
		save := r.off
		f, err := r.next(prev, "system ledger")
		if err != nil {
			return nil, err
		}
		if f > 4 {
			r.off = save
			break
		}
		prev = f
		switch f {
		case 2:
			u, err := r.bytes("system ledger URL")
			if err != nil {
				return nil, err
			}
			l.URL = string(u)
		case 3:
			if l.Index, err = r.uvarint("system ledger index"); err != nil {
				return nil, err
			}
		case 4:
			if l.Time, err = r.varint("system ledger timestamp"); err != nil {
				return nil, err
			}
		}
	}
	if l.URL == "" {
		return nil, errors.New("the system ledger has no URL")
	}
	if l.Index == 0 {
		return nil, errors.New("the system ledger has no block index")
	}
	return l, nil
}

// ed25519Sig is an Accumulate ED25519Signature (protocol.ED25519Signature: 1 type, 2 publicKey, 3 signature, 4 signer, 5 signerVersion, 6 timestamp,
// 7 vote, 8 transactionHash, 9 memo, 10 data), with Metadata the encoding Accumulate hashes for the signature's metadata (Metadata(): the signature and
// the transaction hash cleared, so fields 3 and 8 omitted), cut from the carried bytes.
type ed25519Sig struct {
	PublicKey     []byte
	Signature     []byte
	Signer        string
	SignerVersion uint64
	Vote          uint64
	TxHash        []byte // field 8, when present
	Metadata      []byte
}

func decodeED25519Signature(b []byte) (*ed25519Sig, error) {
	r := &reader{b: b}
	s := &ed25519Sig{}
	var prev uint64
	sawType := false
	keep := make([]byte, 0, len(b))
	for !r.done() {
		start := r.off
		f, err := r.next(prev, "signature")
		if err != nil {
			return nil, err
		}
		prev = f
		switch f {
		case 1:
			t, err := r.uvarint("signature type")
			if err != nil {
				return nil, err
			}
			if t != signatureTypeED25519 {
				return nil, fmt.Errorf("the signature is type %d; only ED25519 (%d) is verified", t, signatureTypeED25519)
			}
			sawType = true
		case 2:
			if s.PublicKey, err = r.bytes("signature public key"); err != nil {
				return nil, err
			}
		case 3:
			if s.Signature, err = r.bytes("signature value"); err != nil {
				return nil, err
			}
		case 4:
			u, err := r.bytes("signature signer")
			if err != nil {
				return nil, err
			}
			s.Signer = string(u)
		case 5:
			if s.SignerVersion, err = r.uvarint("signature signer version"); err != nil {
				return nil, err
			}
		case 6:
			if _, err := r.uvarint("signature timestamp"); err != nil {
				return nil, err
			}
		case 7:
			if s.Vote, err = r.uvarint("signature vote"); err != nil {
				return nil, err
			}
		case 8:
			if s.TxHash, err = r.raw(32, "signature transaction hash"); err != nil {
				return nil, err
			}
		case 9, 10:
			if _, err := r.bytes("signature memo/data"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the signature has unknown field %d", f)
		}
		if f != 3 && f != 8 {
			keep = append(keep, b[start:r.off]...)
		}
	}
	if !sawType {
		return nil, errors.New("the signature has no type")
	}
	if len(s.PublicKey) != 32 || len(s.Signature) != 64 {
		return nil, fmt.Errorf("an ED25519 signature needs a 32-byte key and a 64-byte signature (have %d and %d)", len(s.PublicKey), len(s.Signature))
	}
	if s.Signer == "" {
		return nil, errors.New("the signature names no signer")
	}
	s.Metadata = keep
	return s, nil
}
