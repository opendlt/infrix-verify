// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didaccounts

import "math/bits"

// keccak256 is the legacy Keccak-256 of Ethereum (the 0x01 padding, not SHA3-256's 0x06): Keccak-f[1600] with a rate of 136 bytes. The EIP-55 address checksum is its only caller; it is here because
// this module depends on the standard library only.

var keccakRoundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRotations = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}

var keccakLanes = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakF1600(a *[25]uint64) {
	for round := 0; round < 24; round++ {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[y+x] ^= d
			}
		}
		last := a[1]
		for i := 0; i < 24; i++ {
			lane := keccakLanes[i]
			saved := a[lane]
			a[lane] = bits.RotateLeft64(last, keccakRotations[i])
			last = saved
		}
		for y := 0; y < 25; y += 5 {
			var row [5]uint64
			copy(row[:], a[y:y+5])
			for x := 0; x < 5; x++ {
				a[y+x] ^= ^row[(x+1)%5] & row[(x+2)%5]
			}
		}
		a[0] ^= keccakRoundConstants[round]
	}
}

func keccak256(data []byte) [32]byte {
	const rate = 136
	var state [25]uint64
	absorb := func(block []byte) {
		for i := 0; i < rate/8; i++ {
			var lane uint64
			for j := 0; j < 8; j++ {
				lane |= uint64(block[i*8+j]) << (8 * uint(j))
			}
			state[i] ^= lane
		}
		keccakF1600(&state)
	}
	for len(data) >= rate {
		absorb(data[:rate])
		data = data[rate:]
	}
	last := make([]byte, rate)
	copy(last, data)
	last[len(data)] ^= 0x01
	last[rate-1] ^= 0x80
	absorb(last)
	var out [32]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(state[i] >> (8 * uint(j)))
		}
	}
	return out
}
