// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

const (
	testOutcomeHash = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	testCapsuleHash = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	testAnchorTx    = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
)

func baseExpected() Expected {
	return Expected{OutcomeHash: testOutcomeHash, ReplayCapsuleHash: testCapsuleHash, L0AnchorTxHash: testAnchorTx}
}

// signReceipt builds and signs a witness receipt with the given fields.
func signReceipt(t *testing.T, id, keyPage string, ts int64, mutate func(*Receipt)) Receipt {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	r := Receipt{
		WitnessIdentity:   id,
		WitnessKeyPage:    keyPage,
		RuntimeVersion:    "infrix-witness-test",
		ReplayCapsuleHash: testCapsuleHash,
		OutcomeHash:       testOutcomeHash,
		L0AnchorTxHash:    testAnchorTx,
		ReplayResult:      ReplayReproduced,
		Timestamp:         ts,
	}
	if mutate != nil {
		mutate(&r)
	}
	r.Sign(priv)
	return r
}

// fakeAuthorizer authorizes specific (keyPage, publicKey) pairs and can mark
// some as revoked or return a hard error (to exercise fail-closed).
type fakeAuthorizer struct {
	authorized map[string]bool
	revoked    map[string]bool
	err        error
}

func key(keyPage string, pub []byte) string { return keyPage + "|" + hex.EncodeToString(pub) }

func (f *fakeAuthorizer) Authorize(keyPage string, pub []byte) (KeyPageAuthorization, error) {
	if f.err != nil {
		return KeyPageAuthorization{}, f.err
	}
	k := key(keyPage, pub)
	if f.revoked[k] {
		return KeyPageAuthorization{Revoked: true, Detail: "key removed from page"}, nil
	}
	if f.authorized[k] {
		return KeyPageAuthorization{Authorized: true, Detail: "ok"}, nil
	}
	return KeyPageAuthorization{Revoked: true, Detail: "not on page"}, nil
}

func TestEvaluateAuthorizedAcceptsAuthorizedWitness(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, nil)
	auth := &fakeAuthorizer{authorized: map[string]bool{key(rc.WitnessKeyPage, rc.PublicKey): true}}
	ev := EvaluateAuthorized([]Receipt{rc}, baseExpected(), auth)
	if ev.ValidCount != 1 {
		t.Fatalf("authorized witness should count, got %d (rejected: %v)", ev.ValidCount, ev.Rejected)
	}
}

func TestEvaluateAuthorizedRejectsUnauthorizedKey(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, nil)
	// Authorizer knows nothing about this key → not on page.
	ev := EvaluateAuthorized([]Receipt{rc}, baseExpected(), &fakeAuthorizer{})
	if ev.ValidCount != 0 {
		t.Fatalf("a key not on the page must not count, got %d", ev.ValidCount)
	}
}

func TestEvaluateAuthorizedRejectsRevokedKeyPage(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, nil)
	auth := &fakeAuthorizer{revoked: map[string]bool{key(rc.WitnessKeyPage, rc.PublicKey): true}}
	ev := EvaluateAuthorized([]Receipt{rc}, baseExpected(), auth)
	if ev.ValidCount != 0 {
		t.Fatalf("a revoked witness key must not count, got %d", ev.ValidCount)
	}
	if ev.Rejected[0] == "" {
		t.Error("expected a rejection reason for the revoked key")
	}
}

func TestEvaluateAuthorizedFailsClosedOnLookupError(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, nil)
	auth := &fakeAuthorizer{err: errReturned}
	ev := EvaluateAuthorized([]Receipt{rc}, baseExpected(), auth)
	if ev.ValidCount != 0 {
		t.Fatalf("a key-page lookup error must fail closed (count 0), got %d", ev.ValidCount)
	}
}

func TestEvaluateAuthorizedRejectsDuplicateIdentity(t *testing.T) {
	rc1 := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, nil)
	rc2 := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_001, nil)
	auth := &fakeAuthorizer{authorized: map[string]bool{
		key(rc1.WitnessKeyPage, rc1.PublicKey): true,
		key(rc2.WitnessKeyPage, rc2.PublicKey): true,
	}}
	ev := EvaluateAuthorized([]Receipt{rc1, rc2}, baseExpected(), auth)
	if ev.ValidCount != 1 {
		t.Fatalf("two receipts from one identity must collapse to 1, got %d", ev.ValidCount)
	}
	if len(ev.DuplicateIdentities) != 1 {
		t.Errorf("expected one duplicate identity reported, got %v", ev.DuplicateIdentities)
	}
}

func TestValidateRejectsWrongCapsuleHash(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, func(r *Receipt) {
		r.ReplayCapsuleHash = "deadbeef"
	})
	if err := rc.Validate(baseExpected()); err == nil {
		t.Fatal("a receipt with the wrong replay-capsule hash must be rejected")
	}
}

func TestValidateRejectsWrongL0Tx(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", 1_700_000_000, func(r *Receipt) {
		r.L0AnchorTxHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	})
	if err := rc.Validate(baseExpected()); err == nil {
		t.Fatal("a receipt bound to the wrong L0 anchor tx must be rejected")
	}
}

func TestValidateRejectsStaleReceipt(t *testing.T) {
	now := int64(1_700_000_000)
	exp := baseExpected()
	exp.NowUnix = now
	exp.MaxAgeSeconds = 3600
	// Receipt signed 2 hours ago → stale.
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", now-7200, nil)
	if err := rc.Validate(exp); err == nil {
		t.Fatal("a stale witness receipt (older than MaxAge) must be rejected")
	}
	// A fresh receipt within the window is accepted.
	fresh := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", now-60, nil)
	if err := fresh.Validate(exp); err != nil {
		t.Fatalf("a fresh receipt should validate: %v", err)
	}
}

func TestValidateRejectsFutureReceipt(t *testing.T) {
	now := int64(1_700_000_000)
	exp := baseExpected()
	exp.NowUnix = now
	// Receipt dated well beyond the tolerated skew → rejected.
	rc := signReceipt(t, "acc://w1.acme", "acc://w1.acme/book/1", now+WitnessClockSkewSeconds+60, nil)
	if err := rc.Validate(exp); err == nil {
		t.Fatal("a future-dated witness receipt must be rejected")
	}
}

func TestValidateRejectsMissingKeyPage(t *testing.T) {
	rc := signReceipt(t, "acc://w1.acme", "", 1_700_000_000, nil)
	if err := rc.Validate(baseExpected()); err == nil {
		t.Fatal("a receipt without a witness key page must be rejected")
	}
}

// errReturned is a sentinel for the fail-closed lookup-error test.
var errReturned = &authError{"simulated L0 key-page lookup failure"}

type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }
