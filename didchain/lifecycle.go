// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// THE REACTIVATION COMMITMENT AND THE LEDGER TIMES (infrix core part 25j, raise L2573), rule for rule as core's pkg/did/statementchain/lifecycle.go and pkg/did/ledger_time.go.
//
// A deactivate operation MAY carry reactivationCommitment: the canonical base64 of the SHA-256 of a fresh Ed25519 public key. A deactivation without one is FINAL. A reactivation of a
// committed deactivation carries reactivationKey (the key, canonical base64) and reactivationProof (its Ed25519 signature, canonical base64) over the statement digest computed with the
// reactivate operation's reactivationProof member left out (ProofDigest). deactivate is the only operation of its statement; reactivate is the first, at most once, and the operations
// after it are applied in the same version. An anon reactivation is signed by the committed key itself (it need not be listed in the deactivated document); a chain reactivation is
// signed by the account as every chain statement is, and proven by the committed key.
//
// A history file MAY carry ledgerTimes, one RFC 3339 whole-second UTC time per entry: the ledger's record of when each entry landed. Given them, every entry's stated updated (whole
// seconds) is not after its own ledger time and not before the ledger time of the entry before it, and its stated created is the creation's updated (a first entry of version "1" that is
// not a migration) or else the first entry's created; the verdict then says timesProven. Without them the verdict proves the chain and the documents and nothing about time.

// The member names of the lifecycle operations.
const (
	MemberReactivationCommitment = "reactivationCommitment"
	MemberReactivationKey        = "reactivationKey"
	MemberReactivationProof      = "reactivationProof"
)

// The refusals of the lifecycle and of the ledger times, each a statement-chain or an entry refusal, by its own name (the vectors' reactivation-final, reactivation-key,
// reactivation-proof, time-after-ledger, time-before-predecessor, created-time and ledger-time).
var (
	ErrReactivationFinal     = fmt.Errorf("%w: the deactivation carries no reactivation commitment, so it is final", ErrStatementChain)
	ErrReactivationKey       = fmt.Errorf("%w: the reactivation names no key, or the SHA-256 of its key is not the commitment", ErrStatementChain)
	ErrReactivationProof     = fmt.Errorf("%w: the reactivation proof is absent or is not the committed key's signature over the statement's own digest", ErrStatementChain)
	ErrLifecycleMember       = fmt.Errorf("%w: a lifecycle member is not the canonical base64 of a value of its length", ErrStatementChain)
	ErrTimeAfterLedger       = fmt.Errorf("%w: an entry states an updated time after its ledger time", ErrEntry)
	ErrTimeBeforePredecessor = fmt.Errorf("%w: an entry states an updated time before the ledger time of the entry before it", ErrEntry)
	ErrCreatedTime           = fmt.Errorf("%w: an entry states a created time that is not the first entry's", ErrEntry)
	ErrLedgerTime            = fmt.Errorf("%w: the ledger times are not one whole-second UTC time per entry, in order", ErrEntry)
)

// lifecycleMember reads a byte member of a lifecycle operation: absent is nil; present, the canonical (padded, standard) base64 of exactly size bytes.
func lifecycleMember(op Operation, name string, size int) ([]byte, error) {
	raw, present := op.Object[name]
	if !present {
		return nil, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, fmt.Errorf("%w: %s.%s is not a string", ErrLifecycleMember, op.Type, name)
	}
	value, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(value) != text || len(value) != size {
		return nil, fmt.Errorf("%w: %s.%s is not the canonical base64 of %d bytes", ErrLifecycleMember, op.Type, name, size)
	}
	return value, nil
}

// checkPlacement holds a statement's operations to the places of the lifecycle operations and answers whether it deactivates and whether it reactivates.
func checkPlacement(i int, ops []Operation) (deactivates, reactivates bool, err error) {
	for j, op := range ops {
		switch op.Type {
		case OperationDeactivate:
			if len(ops) != 1 {
				return false, false, chainRefusal(i, "deactivate is the only operation of its statement, and this one carries %d", len(ops))
			}
			deactivates = true
		case OperationReactivate:
			if j != 0 {
				return false, false, chainRefusal(i, "reactivate is the first operation of its statement, and here it is operation %d", j)
			}
			reactivates = true
		}
	}
	return deactivates, reactivates, nil
}

// ProofDigest is the digest a reactivation proof signs: the statement digest of the entry with the reactivate operation's reactivationProof member left out.
func ProofDigest(e *Entry) ([32]byte, error) {
	stripped := *e
	stripped.Operations = make([]Operation, len(e.Operations))
	for i, op := range e.Operations {
		stripped.Operations[i] = op
		if op.Type != OperationReactivate {
			continue
		}
		object := make(map[string]json.RawMessage, len(op.Object))
		for name, value := range op.Object {
			if name != MemberReactivationProof {
				object[name] = value
			}
		}
		stripped.Operations[i] = Operation{Type: op.Type, Object: object}
	}
	return Digest(&stripped)
}

// verifyLifecycle holds an entry's lifecycle members: a deactivation's commitment is well formed; a reactivation proves the commitment of the entry before it, which is the deactivation
// it undoes.
func verifyLifecycle(i int, e, previous *Entry, deactivates, reactivates bool) error {
	switch {
	case deactivates:
		_, err := lifecycleMember(e.Operations[0], MemberReactivationCommitment, sha256.Size)
		return err
	case !reactivates:
		return nil
	}
	commitment, err := lifecycleMember(previous.Operations[0], MemberReactivationCommitment, sha256.Size)
	if err != nil {
		return err
	}
	if commitment == nil {
		return fmt.Errorf("entry %d: %w (version %s)", i, ErrReactivationFinal, previous.VersionID)
	}
	key, err := lifecycleMember(e.Operations[0], MemberReactivationKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(key); key == nil || !bytes.Equal(sum[:], commitment) {
		return fmt.Errorf("entry %d: %w", i, ErrReactivationKey)
	}
	proof, err := lifecycleMember(e.Operations[0], MemberReactivationProof, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	digest, err := ProofDigest(e)
	if err != nil {
		return err
	}
	if proof == nil || !ed25519.Verify(key, digest[:], proof) {
		return fmt.Errorf("entry %d: %w", i, ErrReactivationProof)
	}
	return nil
}

// recoveryKey is the committed key of a reactivation entry (nil for any other entry).
func recoveryKey(e *Entry) []byte {
	if len(e.Operations) == 0 || e.Operations[0].Type != OperationReactivate {
		return nil
	}
	key, _ := lifecycleMember(e.Operations[0], MemberReactivationKey, ed25519.PublicKeySize)
	return key
}

// parseLedgerTimes reads a file's ledgerTimes: none is nil; otherwise one canonical RFC 3339 whole-second UTC time per entry, never decreasing.
func parseLedgerTimes(list []string, entries int) ([]time.Time, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) != entries {
		return nil, fmt.Errorf("%w: %d ledger times for %d entries", ErrLedgerTime, len(list), entries)
	}
	out := make([]time.Time, len(list))
	for i, text := range list {
		at, err := time.Parse(time.RFC3339, text)
		if err != nil || at.UTC().Format(time.RFC3339) != text {
			return nil, fmt.Errorf("%w: ledger time %d %q is not a whole-second UTC time", ErrLedgerTime, i, text)
		}
		out[i] = at.UTC()
		if i > 0 && out[i].Before(out[i-1]) {
			return nil, fmt.Errorf("%w: ledger time %d is before ledger time %d", ErrLedgerTime, i, i-1)
		}
	}
	return out, nil
}

// verifyTimes holds every entry's stated times to the ledger times (registry entries are all format 2: every one states times).
func verifyTimes(history []*Entry, ledger []time.Time) error {
	var created time.Time
	for i, e := range history {
		stated := e.Updated.UTC().Truncate(time.Second)
		if stated.After(ledger[i]) {
			return fmt.Errorf("entry %d: %w: version %s states %s and landed at %s", i, ErrTimeAfterLedger, e.VersionID, e.Updated.UTC().Format(time.RFC3339Nano), ledger[i].Format(time.RFC3339))
		}
		if i > 0 && stated.Before(ledger[i-1]) {
			return fmt.Errorf("entry %d: %w: version %s states %s and the entry before it landed at %s", i, ErrTimeBeforePredecessor, e.VersionID, e.Updated.UTC().Format(time.RFC3339Nano), ledger[i-1].Format(time.RFC3339))
		}
		if i == 0 {
			created = e.Created
			if e.VersionID == "1" {
				created = e.Updated
			}
		}
		if !e.Created.Equal(created) {
			return fmt.Errorf("entry %d: %w", i, ErrCreatedTime)
		}
	}
	return nil
}

var errNoTime = errors.New("the metadata states no time")

// decodeTime reads a metadata time member, as Go's encoder writes it (RFC 3339 with the fraction it has).
func decodeTime(raw json.RawMessage, what string) (time.Time, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return time.Time{}, entryRefuse("%s is not a time: %v", what, errNoTime)
	}
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, entryRefuse("%s is not an RFC 3339 time", what)
	}
	return at, nil
}
