// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof

import (
	"testing"
)

// FZ-01 for the Accumulate binary decoders: no input panics, and a decoder that accepts an input returns only what the bytes say.

func FuzzDecodeAccountHeader(f *testing.F) {
	f.Add([]byte{0x01, 0x0e, 0x02, 0x14, 'a', 'c', 'c', ':', '/', '/', 'd', 'n', '.', 'a', 'c', 'm', 'e', '/', 'l', 'e', 'd', 'g', 'e', 'r'})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x7f})
	f.Fuzz(func(t *testing.T, b []byte) {
		typ, url, err := decodeAccountHeader(b)
		if err == nil && (url == "" || len(url) > len(b)) {
			t.Fatalf("accepted %x as type %d url %q", b, typ, url)
		}
	})
}

func FuzzDecodeTxPrincipal(f *testing.F) {
	f.Add([]byte{0x01, 0x05, 'a', 'c', 'c', ':', '/'})
	f.Add([]byte{0x02, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := decodeTxPrincipal(b)
		if err == nil && (u == "" || len(u) > len(b)) {
			t.Fatalf("accepted %x as %q", b, u)
		}
	})
}

func FuzzCheckWriteDataBody(f *testing.F) {
	f.Add([]byte{0x01, 0x05})
	f.Add([]byte{0x01, 0x05, 0x04, 0x01})
	f.Add([]byte{0x01, 0x05, 0x03, 0x01})
	f.Add([]byte{0x01, 0x05, 0x02, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		if checkWriteDataBody(b) == nil && !(len(b) == 2 || len(b) == 4) {
			t.Fatalf("accepted a %d-byte body %x; a WriteData without its entry is 2 or 4 bytes", len(b), b)
		}
	})
}

// FZ-01 bite: a decoder accepts only the encoding Accumulate writes. The canonical WriteData body decodes; the same value with a padded field number or a
// padded type does not (each padding yields a body the fuzz invariant above would flag as accepted at the wrong length).
func TestFZ01_DecodersAcceptOnlyMinimalVarints(t *testing.T) {
	if err := checkWriteDataBody([]byte{0x01, 0x05}); err != nil {
		t.Fatalf("the canonical body is refused: %v", err)
	}
	for _, b := range [][]byte{{0x81, 0x00, 0x05}, {0x01, 0x85, 0x00}, {0x01, 0x05, 0x84, 0x00, 0x01}} {
		if checkWriteDataBody(b) == nil {
			t.Fatalf("a padded encoding %x was accepted", b)
		}
	}
	if _, _, err := decodeAccountHeader([]byte{0x01, 0x8e, 0x00, 0x02, 0x01, 'x'}); err == nil {
		t.Fatal("a padded account type was accepted")
	}
}

func FuzzDecodeKeyPage(f *testing.F) {
	f.Add([]byte{0x01, 0x09, 0x02, 0x01, 'x', 0x04, 0x01, 0x09, 0x01, 0x80, 0x09, 0x03, 0x02, 0x01, 0x07})
	f.Add([]byte{0x01, 0x09, 0x02, 0x01, 'x', 0x09, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		kp, err := DecodeKeyPage(b)
		if err == nil && (kp.URL == "" || len(kp.Keys) > len(b)) {
			t.Fatalf("accepted %x as %+v", b, kp)
		}
	})
}
