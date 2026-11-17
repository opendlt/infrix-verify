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
	"math/big"
	"strings"
	"testing"
)

// THE CUT OF CORE PART 25j (agent 25j2): each survivor of the didchain table held by its own observation.

func TestARefusedPlacementAnswersNeitherDeactivationNorReactivation(t *testing.T) {
	for name, ops := range map[string][]Operation{
		"deactivate beside another": {lifeOp(OperationDeactivate, nil), lifeOp("addService", nil)},
		"reactivate after another":  {lifeOp("addService", nil), lifeOp(OperationReactivate, nil)},
	} {
		d, r, err := checkPlacement(1, ops)
		if err == nil || d || r {
			t.Errorf("%s: deactivates=%t reactivates=%t err=%v, want neither and a refusal", name, d, r, err)
		}
	}
}

func TestTheProofDigestLeavesOutOnlyTheReactivationsProof(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	proof := b64(make([]byte, ed25519.SignatureSize))
	e := &Entry{DID: "did:x", NetworkID: "n", VersionID: "4", Sequence: 4, Operations: []Operation{
		lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(key), MemberReactivationProof: proof}),
		lifeOp("addService", map[string]string{MemberReactivationProof: proof}),
	}}
	got, err := ProofDigest(e)
	if err != nil {
		t.Fatal(err)
	}
	stripped := *e
	stripped.Operations = []Operation{lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(key)}), e.Operations[1]}
	want, err := Digest(&stripped)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("the proof digest left out a member of an operation that is not the reactivation")
	}
}

func TestAReactivationWhoseStatementHasNoCanonicalFormIsRefusedByThatWord(t *testing.T) {
	recovery := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := recovery.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	deactivation := &Entry{VersionID: "3", Deactivated: true, Operations: []Operation{lifeOp(OperationDeactivate, map[string]string{MemberReactivationCommitment: b64(sum[:])})}}
	e := &Entry{VersionID: "4", Operations: []Operation{
		lifeOp(OperationReactivate, map[string]string{MemberReactivationKey: b64(pub), MemberReactivationProof: b64(make([]byte, ed25519.SignatureSize))}),
		{Type: "addService", Object: map[string]json.RawMessage{"type": json.RawMessage(`"addService"`), "n": json.RawMessage("1e400")}},
	}}
	err := verifyLifecycle(4, e, deactivation, false, true)
	if !errors.Is(err, ErrStatementChain) || errors.Is(err, ErrReactivationProof) || !strings.Contains(err.Error(), "has no canonical form") {
		t.Fatalf("a reactivation whose statement has no canonical form: %v", err)
	}
}

func TestALedgerTimeBackInTimeNamesBothTimes(t *testing.T) {
	_, err := parseLedgerTimes([]string{"2026-01-01T00:00:00Z", "2026-01-01T00:00:02Z", "2026-01-01T00:00:01Z"}, 3)
	if !errors.Is(err, ErrLedgerTime) || !strings.Contains(err.Error(), "ledger time 2 is before ledger time 1") {
		t.Fatalf("a ledger time back in time: %v", err)
	}
}

func TestOnlyTheDoublingOfAPointWithYZeroIsAnsweredAsInfinity(t *testing.T) {
	// a pair with one y = 0 is not the doubling of a y = 0 point: the sum is the doubling of a (y = 1), never the point at infinity
	a, b := secpPoint{x: big.NewInt(5), y: big.NewInt(1)}, secpPoint{x: big.NewInt(5), y: big.NewInt(0)}
	if got := secpAdd(a, b); got.inf {
		t.Fatal("a pair with one y = 0 answered as the point at infinity")
	}
	if got, want := secpAdd(a, b), secpAdd(a, a); got.x.Cmp(want.x) != 0 || got.y.Cmp(want.y) != 0 {
		t.Fatalf("the pair is %v, the doubling of a %v", got, want)
	}
}

func TestTheValidAnonHistoryIsHeldByItsReactivationSignatureAndItsLedgerTimes(t *testing.T) {
	var ok AnonHistory
	for _, v := range loadVectors(t).AnonHistory {
		if v.Valid {
			ok = v.History
		}
	}
	tail := len(ok.Entries) - 1
	raw, _ := base64.StdEncoding.DecodeString(ok.Entries[tail])
	var entry map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&entry); err != nil {
		t.Fatal(err)
	}
	statement := entry["statement"].(map[string]any)
	if ops := statement["operations"].([]any); ops[0].(map[string]any)["type"] != OperationReactivate {
		t.Fatalf("the valid history's tail is not the reactivation: %v", ops[0])
	}
	signature, _ := base64.StdEncoding.DecodeString(statement["signature"].(string))
	signature[0] ^= 1
	statement["signature"] = base64.StdEncoding.EncodeToString(signature)
	out, _ := json.Marshal(entry)
	tampered := ok
	tampered.Entries = append([]string(nil), ok.Entries...)
	tampered.Entries[tail] = base64.StdEncoding.EncodeToString(out)
	if _, err := VerifyAnonHistory(&tampered); !errors.Is(err, ErrStatementChain) || !strings.Contains(err.Error(), "does not verify over the statement digest") {
		t.Errorf("the reactivation signed by the recovery key with a changed signature: %v", err)
	}

	untimed := ok
	untimed.LedgerTimes = nil
	verdict, err := VerifyAnonHistory(&untimed)
	if err != nil || !verdict.Verified || verdict.TimesProven || verdict.TailLedgerTime != "" {
		t.Errorf("the history without ledger times: %+v %v, want verified with no time proven", verdict, err)
	}

	badTimes := ok
	badTimes.LedgerTimes = append([]string{"x"}, ok.LedgerTimes[1:]...)
	if _, err := VerifyAnonHistory(&badTimes); !errors.Is(err, ErrLedgerTime) {
		t.Errorf("ledger times that do not parse: %v", err)
	}
}
