// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// THE REACTIVATION COMMITMENT AND THE LEDGER TIMES (core part 25j): each refusal by its own words, as core's statementchain and ledger_time hold them.

func lifeOp(t string, members map[string]string) Operation {
	object := map[string]json.RawMessage{"type": json.RawMessage(`"` + t + `"`)}
	for name, value := range members {
		raw, _ := json.Marshal(value)
		object[name] = raw
	}
	return Operation{Type: t, Object: object}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestAReactivationIsHeldToTheCommitmentOfTheDeactivationItUndoes(t *testing.T) {
	recovery := ed25519.NewKeyFromSeed(make([]byte, 32))
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	pub := recovery.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	deactivation := &Entry{VersionID: "3", Deactivated: true, Operations: []Operation{lifeOp(OperationDeactivate, map[string]string{MemberReactivationCommitment: b64(sum[:])})}}
	final := &Entry{VersionID: "3", Deactivated: true, Operations: []Operation{lifeOp(OperationDeactivate, nil)}}
	reactivation := func(key ed25519.PublicKey, prover ed25519.PrivateKey, mutate func(e *Entry)) *Entry {
		e := &Entry{DID: "did:x", NetworkID: "n", VersionID: "4", Sequence: 4, PredecessorStorageHash: []byte{1}, DocumentHash: []byte{2},
			Operations: []Operation{lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(key)}), lifeOp("addService", nil)}}
		if mutate != nil {
			mutate(e)
		}
		digest, err := ProofDigest(e)
		if err != nil {
			t.Fatal(err)
		}
		e.Operations[0] = lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(key), MemberReactivationProof: b64(ed25519.Sign(prover, digest[:]))})
		return e
	}
	if err := verifyLifecycle(4, reactivation(pub, recovery, nil), deactivation, false, true); err != nil {
		t.Fatalf("the committed key's proof: %v", err)
	}
	if got := recoveryKey(reactivation(pub, recovery, nil)); string(got) != string(pub) {
		t.Fatalf("the recovery key %x", got)
	}
	if recoveryKey(deactivation) != nil || recoveryKey(&Entry{}) != nil {
		t.Fatal("an entry that does not reactivate has a recovery key")
	}
	moved := reactivation(pub, recovery, func(e *Entry) { e.Sequence = 9 }) // a proof made for another statement
	moved.Sequence = 4
	for name, c := range map[string]struct {
		e, previous *Entry
		want        error
	}{
		"a final deactivation":               {reactivation(pub, recovery, nil), final, ErrReactivationFinal},
		"another key":                        {reactivation(other.Public().(ed25519.PublicKey), other, nil), deactivation, ErrReactivationKey},
		"no key":                             {&Entry{Operations: []Operation{lifeOp(OperationReactivate, nil)}}, deactivation, ErrReactivationKey},
		"the committed key, another's proof": {reactivation(pub, other, nil), deactivation, ErrReactivationProof},
		"the committed key, no proof":        {&Entry{Operations: []Operation{lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(pub)})}}, deactivation, ErrReactivationProof},
		"a proof over another digest":        {moved, deactivation, ErrReactivationProof},
		"a commitment of another length":     {reactivation(pub, recovery, nil), &Entry{Operations: []Operation{lifeOp(OperationDeactivate, map[string]string{MemberReactivationCommitment: "AAAA"})}}, ErrLifecycleMember},
		"a key in another alphabet":          {&Entry{Operations: []Operation{lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: base64.RawURLEncoding.EncodeToString(pub)})}}, deactivation, ErrLifecycleMember},
		"a proof of another length":          {&Entry{Operations: []Operation{lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(pub), MemberReactivationProof: "AAAA"})}}, deactivation, ErrLifecycleMember},
	} {
		if err := verifyLifecycle(4, c.e, c.previous, false, true); !errors.Is(err, c.want) || !errors.Is(err, ErrStatementChain) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if err := verifyLifecycle(3, &Entry{Operations: []Operation{lifeOp(OperationDeactivate, map[string]string{MemberReactivationCommitment: "x"})}}, nil, true, false); !errors.Is(err, ErrLifecycleMember) {
		t.Errorf("a deactivation whose commitment is not base64: %v", err)
	}
	if err := verifyLifecycle(3, &Entry{}, nil, false, false); err != nil {
		t.Errorf("an entry that neither deactivates nor reactivates: %v", err)
	}
	bad := Operation{Type: OperationReactivate, Object: map[string]json.RawMessage{MemberReactivationKey: json.RawMessage(`7`)}}
	if _, err := lifecycleMember(bad, MemberReactivationKey, 32); !errors.Is(err, ErrLifecycleMember) || !strings.Contains(err.Error(), "is not a string") {
		t.Errorf("a member that is not a string: %v", err)
	}
	// the places of the lifecycle operations
	for name, c := range map[string]struct {
		ops   []Operation
		words string
	}{
		"deactivate beside another": {[]Operation{lifeOp(OperationDeactivate, nil), lifeOp("addService", nil)}, "deactivate is the only operation"},
		"reactivate after another":  {[]Operation{lifeOp("addService", nil), lifeOp(OperationReactivate, nil)}, "reactivate is the first operation"},
		"reactivate twice":          {[]Operation{lifeOp(OperationReactivate, nil), lifeOp(OperationReactivate, nil)}, "reactivate is the first operation"},
	} {
		if _, _, err := checkPlacement(1, c.ops); !errors.Is(err, ErrStatementChain) || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if d, r, err := checkPlacement(1, []Operation{lifeOp(OperationReactivate, nil), lifeOp("addService", nil)}); d || !r || err != nil {
		t.Errorf("a reactivation with a rotation: %v %v %v", d, r, err)
	}
}

func TestTheStatedTimesAreHeldToTheLedgerTimesTheFileCarries(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 19, 41, 30, 0, time.UTC)
	entry := func(version string, updated, created time.Time) *Entry {
		return &Entry{VersionID: version, Updated: updated, Created: created}
	}
	if err := verifyTimes([]*Entry{entry("1", t0.Add(700*time.Millisecond), t0.Add(700*time.Millisecond)), entry("2", t0.Add(5*time.Second), t0.Add(700*time.Millisecond))}, []time.Time{t0, t0.Add(6 * time.Second)}); err != nil {
		t.Fatalf("a stamp in the second of its block: %v", err)
	}
	if err := verifyTimes([]*Entry{entry("7", t0, t0.Add(-time.Hour))}, []time.Time{t0}); err != nil {
		t.Fatalf("a history that begins after its creation: %v", err)
	}
	for name, c := range map[string]struct {
		history []*Entry
		ledger  []time.Time
		want    error
	}{
		"after it landed":            {[]*Entry{entry("1", t0.Add(time.Second), t0.Add(time.Second))}, []time.Time{t0}, ErrTimeAfterLedger},
		"before the one before":      {[]*Entry{entry("1", t0, t0), entry("2", t0.Add(-time.Second), t0)}, []time.Time{t0, t0.Add(time.Minute)}, ErrTimeBeforePredecessor},
		"a creation not its updated": {[]*Entry{entry("1", t0, t0.Add(-time.Hour))}, []time.Time{t0}, ErrCreatedTime},
		"another created later":      {[]*Entry{entry("1", t0, t0), entry("2", t0.Add(time.Second), t0.Add(time.Second))}, []time.Time{t0, t0.Add(time.Second)}, ErrCreatedTime},
	} {
		if err := verifyTimes(c.history, c.ledger); !errors.Is(err, c.want) || !errors.Is(err, ErrEntry) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	for name, list := range map[string][]string{
		"another count": {"2026-01-01T00:00:00Z"}, "not a time": {"x", "y"}, "a fraction": {"2026-01-01T00:00:00.5Z", "2026-01-01T00:00:01Z"},
		"back in time": {"2026-01-01T00:00:01Z", "2026-01-01T00:00:00Z"},
	} {
		if _, err := parseLedgerTimes(list, 2); !errors.Is(err, ErrLedgerTime) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := parseLedgerTimes(nil, 2); got != nil || err != nil {
		t.Errorf("no ledger times: %v %v", got, err)
	}
	if _, err := decodeTime(json.RawMessage(`7`), "metadata.updated"); !errors.Is(err, ErrEntry) {
		t.Errorf("a time that is not a string: %v", err)
	}
	if _, err := decodeTime(json.RawMessage(`"yesterday"`), "metadata.updated"); !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), "not an RFC 3339 time") {
		t.Errorf("a time that does not parse: %v", err)
	}
}
