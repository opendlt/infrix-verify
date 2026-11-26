// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// The protobuf encodings CometBFT hashes and signs, written out by hand so the verifier carries no protobuf runtime. Each one cites the CometBFT v0.38 source
// it reproduces (Kermit runs v0.38.0-rc3); the differential suite (DF-02) holds every one of them byte-for-byte to CometBFT's own.

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
)

func appendTag(b []byte, field, wire int) []byte {
	return binary.AppendUvarint(b, uint64(field)<<3|uint64(wire))
}

// appendVarint writes a proto3 varint field; proto3 omits a zero.
func appendVarint(b []byte, field int, v uint64) []byte {
	if v == 0 {
		return b
	}
	return binary.AppendUvarint(appendTag(b, field, wireVarint), v)
}

// appendSfixed64 writes a proto3 sfixed64 field (little-endian, 8 bytes); proto3 omits a zero.
func appendSfixed64(b []byte, field int, v int64) []byte {
	if v == 0 {
		return b
	}
	return binary.LittleEndian.AppendUint64(appendTag(b, field, wireFixed64), uint64(v))
}

// appendBytes writes a proto3 bytes or string field; proto3 omits an empty one.
func appendBytes(b []byte, field int, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	return appendMessage(b, field, v)
}

// appendMessage writes an embedded message unconditionally, which is what gogoproto generates for a non-nullable field (and for a non-nil nullable one).
func appendMessage(b []byte, field int, msg []byte) []byte {
	b = binary.AppendUvarint(appendTag(b, field, wireBytes), uint64(len(msg)))
	return append(b, msg...)
}

// encodeTimestamp is gogoproto's StdTimeMarshal: google.protobuf.Timestamp{seconds = 1, nanos = 2}.
func encodeTimestamp(t Timestamp) []byte {
	var b []byte
	b = appendVarint(b, 1, uint64(t.Seconds))
	b = appendVarint(b, 2, uint64(int64(t.Nanos)))
	return b
}

// encodePartSetHeader is cometbft.types.v1.PartSetHeader{total = 1 (uint32), hash = 2}; CanonicalPartSetHeader has the same layout.
func encodePartSetHeader(p PartSetHeader) []byte {
	var b []byte
	b = appendVarint(b, 1, uint64(p.Total))
	b = appendBytes(b, 2, p.Hash)
	return b
}

// encodeBlockID is types.BlockID.ToProto().Marshal(): hash = 1, part_set_header = 2 (non-nullable, so always written). CanonicalBlockID has the same layout.
func encodeBlockID(id BlockID) []byte {
	var b []byte
	b = appendBytes(b, 1, id.Hash)
	b = appendMessage(b, 2, encodePartSetHeader(id.PartSetHeader))
	return b
}

// cdcString, cdcInt64 and cdcBytes are types/encoding_helper.go cdcEncode: the gogo wrapper types StringValue, Int64Value and BytesValue, field 1, and
// nothing at all for an empty value.
func cdcString(s string) []byte { return appendBytes(nil, 1, []byte(s)) }
func cdcInt64(v int64) []byte   { return appendVarint(nil, 1, uint64(v)) }
func cdcBytes(v []byte) []byte  { return appendBytes(nil, 1, v) }

// merkleRoot is crypto/merkle.HashFromByteSlices (RFC 6962 with a 0x00 leaf prefix and a 0x01 inner prefix, split at the largest power of two below n).
func merkleRoot(items [][]byte) []byte {
	switch len(items) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		h := sha256.Sum256(append([]byte{0}, items[0]...))
		return h[:]
	}
	k := splitPoint(len(items))
	left, right := merkleRoot(items[:k]), merkleRoot(items[k:])
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(append(append(buf, 1), left...), right...)
	h := sha256.Sum256(buf)
	return h[:]
}

func splitPoint(n int) int {
	k := 1 << (bits.Len(uint(n)) - 1)
	if k == n {
		k >>= 1
	}
	return k
}
