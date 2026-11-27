// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import "fmt"

// accountTypeKeyBook is protocol.AccountTypeKeyBook.
const accountTypeKeyBook = 10

// KeyBook is a key book's main state as the verifier reads it from the exact bytes an AccountProof commits (protocol.KeyBook, protocol/types_gen.go):
// its page count, which proves that every page index past it does not exist (infrix-core L3196). Read it only from an AccountProof whose State has
// been verified, so the bytes are the book's.
type KeyBook struct {
	URL       string
	BookType  uint64
	PageCount uint64
}

// DecodeKeyBook reads a key book's main state. Fields are read in the order Accumulate writes them (KeyBook.MarshalBinary: type, url, book type,
// account auth, page count); any other field, an out-of-order or repeated field, a padded varint or trailing bytes is refused.
func DecodeKeyBook(main []byte) (*KeyBook, error) {
	typ, url, err := decodeAccountHeader(main)
	if err != nil {
		return nil, err
	}
	if typ != accountTypeKeyBook {
		return nil, fmt.Errorf("the account is type %d, not a key book", typ)
	}
	kb := &KeyBook{URL: url}
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
		f, err := r.uvarint("key book field")
		if err != nil {
			return nil, err
		}
		if f <= last {
			return nil, fmt.Errorf("key book field %d is out of order or repeated", f)
		}
		last = f
		switch f {
		case 3:
			if kb.BookType, err = r.uvarint("book type"); err != nil {
				return nil, err
			}
		case 4:
			// the account's authorities: committed with the state, not read by a page-count proof
			if _, err := r.str("account auth"); err != nil {
				return nil, err
			}
		case 5:
			if kb.PageCount, err = r.uvarint("page count"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the key book has unknown field %d", f)
		}
	}
	return kb, nil
}
