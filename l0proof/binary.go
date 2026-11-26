// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The few Accumulate binary encodings the verifier reads (pkg/types/encoding writer.go): a field is its number as a uvarint, then its value; an enum,
// uint or bool is a uvarint; a string, URL or byte string is a uvarint length and the bytes. Empty fields are omitted. The verifier only ever READS these
// bytes, to learn whose they are; every hash is taken over the exact bytes carried, so a re-encoding can never stand in for them.

// Accumulate protocol enum values (protocol/enums_gen.go).
const (
	accountTypeSystemLedger  = 14
	transactionTypeWriteData = 5
)

type reader struct {
	b   []byte
	off int
}

func (r *reader) done() bool { return r.off == len(r.b) }

func (r *reader) uvarint(what string) (uint64, error) {
	v, n := binary.Uvarint(r.b[r.off:])
	if n <= 0 {
		return 0, fmt.Errorf("%s: malformed varint at byte %d", what, r.off)
	}
	// Accumulate writes minimal varints (binary.PutUvarint); a padded one is not an encoding Accumulate produced, so it is refused
	if n != len(binary.AppendUvarint(nil, v)) {
		return 0, fmt.Errorf("%s: non-minimal varint at byte %d", what, r.off)
	}
	r.off += n
	return v, nil
}

// field reads the next field number and requires it to be want.
func (r *reader) field(want uint64, what string) error {
	if r.done() {
		return fmt.Errorf("%s: field %d is missing", what, want)
	}
	f, err := r.uvarint(what)
	if err != nil {
		return err
	}
	if f != want {
		return fmt.Errorf("%s: found field %d where field %d is required", what, f, want)
	}
	return nil
}

func (r *reader) str(what string) (string, error) {
	n, err := r.uvarint(what)
	if err != nil {
		return "", err
	}
	if n > uint64(len(r.b)-r.off) {
		return "", fmt.Errorf("%s: a %d-byte string overruns the encoding", what, n)
	}
	s := string(r.b[r.off : r.off+int(n)])
	r.off += int(n)
	return s, nil
}

// decodeAccountHeader reads an account's main-state encoding far enough to learn its type (field 1, an enum) and URL (field 2, a string). Every account
// type in protocol/types_gen.go writes exactly these two first.
func decodeAccountHeader(main []byte) (uint64, string, error) {
	r := &reader{b: main}
	if err := r.field(1, "account type"); err != nil {
		return 0, "", err
	}
	typ, err := r.uvarint("account type")
	if err != nil {
		return 0, "", err
	}
	if err := r.field(2, "account URL"); err != nil {
		return 0, "", err
	}
	u, err := r.str("account URL")
	if err != nil {
		return 0, "", err
	}
	if u == "" {
		return 0, "", errors.New("account URL is empty")
	}
	return typ, u, nil
}

// decodeTxPrincipal reads a transaction header's principal (TransactionHeader field 1, a URL), which every transaction carries.
func decodeTxPrincipal(header []byte) (string, error) {
	r := &reader{b: header}
	if err := r.field(1, "transaction principal"); err != nil {
		return "", err
	}
	u, err := r.str("transaction principal")
	if err != nil {
		return "", err
	}
	if u == "" {
		return "", errors.New("transaction principal is empty")
	}
	return u, nil
}

// checkWriteDataBody requires the body to be a WriteData with its entry removed, as WriteData.GetHash hashes it: field 1 is the WriteData type; field 2
// (the entry) must be absent, since the entry is carried and hashed separately; field 3 (scratch) must be absent, since a scratch entry is pruned and so
// cannot anchor anything; field 4 (write to state) may be present and true. Nothing may follow.
func checkWriteDataBody(body []byte) error {
	r := &reader{b: body}
	if err := r.field(1, "transaction body type"); err != nil {
		return err
	}
	typ, err := r.uvarint("transaction body type")
	if err != nil {
		return err
	}
	if typ != transactionTypeWriteData {
		return fmt.Errorf("the transaction is type %d, not WriteData (%d)", typ, transactionTypeWriteData)
	}
	if r.done() {
		return nil
	}
	f, err := r.uvarint("WriteData field")
	if err != nil {
		return err
	}
	switch f {
	case 2:
		return errors.New("the WriteData body still carries its entry; the entry must be carried separately")
	case 3:
		return errors.New("the WriteData is a scratch write, which is pruned and cannot anchor")
	case 4:
		v, err := r.uvarint("WriteData writeToState")
		if err != nil {
			return err
		}
		if v != 1 {
			return fmt.Errorf("WriteData writeToState is %d; a written bool is 1", v)
		}
	default:
		return fmt.Errorf("the WriteData body has unknown field %d", f)
	}
	if !r.done() {
		return errors.New("the WriteData body has trailing bytes")
	}
	return nil
}
