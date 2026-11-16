// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"errors"
	"math/big"
)

// secp256k1 (SEC 2 section 2.4.1) on math/big, written here because the standard library has no secp256k1 and this module depends on the standard library only. It VERIFIES public
// signatures and recovers public keys, so it handles no secret and needs no constant-time arithmetic: the curve y^2 = x^3 + 7 over the prime field p, the generator G of prime order n
// (cofactor 1). It is held to the standards' published values and to the core verifier's vectors (secp256k1_test.go, verifiers_test.go).

var (
	secpP, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	secpN, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secpGx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	secpGy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
	secpG     = secpPoint{x: secpGx, y: secpGy}
	// secpHalfN is n/2: a low-s signature has s at most this (EIP-2, BIP-62/146)
	secpHalfN = new(big.Int).Rsh(secpN, 1)
	// secpSqrtExp is (p+1)/4: p = 3 mod 4, so a square root of a is a^((p+1)/4)
	secpSqrtExp = new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2)
)

// secpPoint is an affine point of the curve; the point at infinity has inf set.
type secpPoint struct {
	x, y *big.Int
	inf  bool
}

// ErrSecp256k1 is every refusal of this file: a key or a signature that is not one of the curve.
var ErrSecp256k1 = errors.New("not a secp256k1 key or signature")

func modP(v *big.Int) *big.Int { return v.Mod(v, secpP) }

func secpAdd(a, b secpPoint) secpPoint {
	switch {
	case a.inf:
		return b
	case b.inf:
		return a
	}
	var slope *big.Int
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Add(a.y, b.y).Cmp(secpP) == 0 || a.y.Sign() == 0 && b.y.Sign() == 0 {
			return secpPoint{inf: true}
		}
		// doubling: slope = 3x^2 / 2y
		num := modP(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x)))
		slope = modP(num.Mul(num, new(big.Int).ModInverse(modP(new(big.Int).Lsh(a.y, 1)), secpP)))
	} else {
		num := modP(new(big.Int).Sub(b.y, a.y))
		slope = modP(num.Mul(num, new(big.Int).ModInverse(modP(new(big.Int).Sub(b.x, a.x)), secpP)))
	}
	x := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(slope, slope), a.x), b.x))
	y := modP(new(big.Int).Sub(new(big.Int).Mul(slope, new(big.Int).Sub(a.x, x)), a.y))
	return secpPoint{x: x, y: y}
}

// secpMul is k*P by double-and-add (public inputs only).
func secpMul(p secpPoint, k *big.Int) secpPoint {
	out := secpPoint{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		out = secpAdd(out, out)
		if k.Bit(i) == 1 {
			out = secpAdd(out, p)
		}
	}
	return out
}

// secpOnCurve reports whether (x, y), both below p, satisfies y^2 = x^3 + 7.
func secpOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(secpP) >= 0 || y.Cmp(secpP) >= 0 {
		return false
	}
	rhs := modP(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), secpP), big.NewInt(7)))
	return modP(new(big.Int).Mul(y, y)).Cmp(rhs) == 0
}

// secpLift is the point of x-coordinate x whose y has the parity odd, or false when no point has that x.
func secpLift(x *big.Int, odd bool) (secpPoint, bool) {
	if x.Cmp(secpP) >= 0 {
		return secpPoint{}, false
	}
	rhs := modP(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), secpP), big.NewInt(7)))
	y := new(big.Int).Exp(rhs, secpSqrtExp, secpP)
	if modP(new(big.Int).Mul(y, y)).Cmp(rhs) != 0 {
		return secpPoint{}, false
	}
	if (y.Bit(0) == 1) != odd {
		y.Sub(secpP, y)
	}
	return secpPoint{x: new(big.Int).Set(x), y: y}, true
}

// ParseSecp256k1PublicKey reads a SEC 1 public key: 33 bytes compressed (0x02 or 0x03 and x) or 65 bytes uncompressed (0x04, x and y), a point of the curve.
func ParseSecp256k1PublicKey(raw []byte) (secpPoint, error) {
	switch {
	case len(raw) == 33 && (raw[0] == 2 || raw[0] == 3):
		p, ok := secpLift(new(big.Int).SetBytes(raw[1:]), raw[0] == 3)
		if !ok {
			return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("the compressed key's x is not the x of a curve point"))
		}
		return p, nil
	case len(raw) == 65 && raw[0] == 4:
		x, y := new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:])
		if !secpOnCurve(x, y) {
			return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("the uncompressed key is not a curve point"))
		}
		return secpPoint{x: x, y: y}, nil
	}
	return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("a SEC 1 public key is 33 bytes (0x02 or 0x03) or 65 bytes (0x04)"))
}

// serializeUncompressed is 0x04 || x || y, 65 bytes.
func (p secpPoint) serializeUncompressed() []byte {
	out := make([]byte, 65)
	out[0] = 4
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out
}

// serializeCompressed is 0x02 or 0x03 (the parity of y) || x, 33 bytes.
func (p secpPoint) serializeCompressed() []byte {
	out := make([]byte, 33)
	out[0] = 2 + byte(p.y.Bit(0))
	p.x.FillBytes(out[1:])
	return out
}

// secpScalars reads r || s (64 bytes) as two scalars and refuses zero, a value at or above n, and an s above n/2 (the malleated twin of a low-s signature).
func secpScalars(rs []byte) (r, s *big.Int, err error) {
	if len(rs) != 64 {
		return nil, nil, errors.Join(ErrSecp256k1, errors.New("r || s is not 64 bytes"))
	}
	r, s = new(big.Int).SetBytes(rs[:32]), new(big.Int).SetBytes(rs[32:])
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 {
		return nil, nil, errors.Join(ErrSecp256k1, errors.New("r is zero or not below the order"))
	}
	if s.Sign() == 0 || s.Cmp(secpN) >= 0 {
		return nil, nil, errors.Join(ErrSecp256k1, errors.New("s is zero or not below the order"))
	}
	if s.Cmp(secpHalfN) > 0 {
		return nil, nil, errors.Join(ErrSecp256k1, errors.New("s is in the upper half of the order: the malleated twin of a low-s signature"))
	}
	return r, s, nil
}

// VerifySecp256k1 verifies a low-s ECDSA signature r || s of a 32-byte hash under a public key (SEC 1 section 4.1.4).
func VerifySecp256k1(key secpPoint, hash, rs []byte) bool {
	r, s, err := secpScalars(rs)
	if err != nil || len(hash) != 32 || key.inf {
		return false
	}
	e := new(big.Int).SetBytes(hash)
	w := new(big.Int).ModInverse(s, secpN)
	u1 := new(big.Int).Mod(new(big.Int).Mul(e, w), secpN)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), secpN)
	point := secpAdd(secpMul(secpG, u1), secpMul(key, u2))
	return !point.inf && new(big.Int).Mod(point.x, secpN).Cmp(r) == 0
}

// RecoverSecp256k1 recovers the public key of a low-s signature r || s of a 32-byte hash with a recovery id 0 to 3 (SEC 1 section 4.1.6): R is the point of x = r + (id/2)*n whose y
// has the parity id%2, and the key is r^-1 (sR - eG). The recovered key verifies the signature.
func RecoverSecp256k1(rs []byte, recovery byte, hash []byte) (secpPoint, error) {
	r, s, err := secpScalars(rs)
	if err != nil {
		return secpPoint{}, err
	}
	if recovery > 3 {
		return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("the recovery id is not 0 to 3"))
	}
	if len(hash) != 32 {
		return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("the hash is not 32 bytes"))
	}
	x := new(big.Int).Set(r)
	if recovery >= 2 {
		x.Add(x, secpN)
	}
	point, ok := secpLift(x, recovery%2 == 1)
	if !ok {
		return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("no curve point has the x the signature and recovery id name"))
	}
	e := new(big.Int).SetBytes(hash)
	negE := new(big.Int).Mod(new(big.Int).Neg(e), secpN)
	rInv := new(big.Int).ModInverse(r, secpN)
	key := secpMul(secpAdd(secpMul(point, s), secpMul(secpG, negE)), rInv)
	if key.inf || !VerifySecp256k1(key, hash, rs) {
		return secpPoint{}, errors.Join(ErrSecp256k1, errors.New("the signature recovers no key that verifies it"))
	}
	return key, nil
}
