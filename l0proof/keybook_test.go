// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import "testing"

// s28cuKeyBook is a key book's main state in Accumulate's encoding (KeyBook.MarshalBinary): type 10, url, account auth (an empty object), page count.
func s28cuKeyBook(url string, tail ...byte) []byte {
	b := []byte{0x01, accountTypeKeyBook, 0x02, byte(len(url))}
	b = append(b, url...)
	return append(b, tail...)
}

// A KEY BOOK'S PAGE COUNT IS READ FROM ITS EXACT BYTES (infrix-core L3196): the count a proven book states makes every page past it a proven
// absence, so the decoder reads only the fields Accumulate writes, in its order, and refuses anything else.
func TestS28cuTheKeyBookDecoderReadsThePageCountAndNothingElse(t *testing.T) {
	const url = "acc://s28cu.acme/book"
	kb, err := DecodeKeyBook(s28cuKeyBook(url, 0x04, 0x01, emptyObject, 0x05, 0x02))
	if err != nil || kb.URL != url || kb.PageCount != 2 {
		t.Fatalf("decode = %+v, %v; want %s with 2 pages", kb, err, url)
	}
	if kb, err := DecodeKeyBook(s28cuKeyBook(url, 0x03, 0x01, 0x04, 0x01, emptyObject)); err != nil || kb.PageCount != 0 || kb.BookType != 1 {
		t.Fatalf("a book with no pages and a book type = %+v, %v", kb, err)
	}
	for name, raw := range map[string][]byte{
		"an unknown field":   s28cuKeyBook(url, 0x05, 0x02, 0x06, 0x01),
		"an out-of-order":    s28cuKeyBook(url, 0x05, 0x02, 0x04, 0x01, emptyObject),
		"a repeated field":   s28cuKeyBook(url, 0x05, 0x02, 0x05, 0x03),
		"a truncated count":  s28cuKeyBook(url, 0x05),
		"a key page's state": append([]byte{0x01, 9, 0x02, byte(len(url))}, url...),
	} {
		if kb, err := DecodeKeyBook(raw); err == nil {
			t.Errorf("%s decoded as %+v", name, kb)
		}
	}
}
