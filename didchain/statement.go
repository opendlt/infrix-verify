// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package didchain verifies the statement chains of did:infrix's anon and chain profiles, node-free and standard-library only: the second implementation of infrix core's
// pkg/did/statementchain, its canonical form (jcs.go), the anon authorizer and the four namespace verifiers of the chain profile (verifiers.go), so that anyone can check a history
// without trusting the node that served it (infrix core part 25g, row H3, ledger raise L2557). Every rule is core's, stated here as the bytes a verifier reads:
//
// THE STATEMENT DIGEST of an entry is
//
//	SHA-256( "infrix:did-statement:v1\x00" || lp(DID) || lp(NetworkID) || lp(VersionID) || be64(Sequence) || lp(PredecessorStorageHash) ||
//	         be64(count) || for each operation: lp(type) || lp(JCS(the stored operation without its "type" member)) || lp(DocumentHash) )
//
// where lp(x) is the 8-byte big-endian length of x and x, and JCS is RFC 8785 with the I-JSON refusals of jcs.go.
//
// A REGISTRY ENTRY is the JSON of a v2 storage envelope (version 2, hashAlgorithm "sha-256/jcs-rfc8785") carrying the document, its metadata (versionId, deactivated), the document hash
// (base64; SHA-256 of JCS of the "document" member AS STORED), the identity binding (canonicalDid, accountUrl, networkId), the predecessor binding (versionId, documentHash, storageHash;
// absent for the genesis) and the statement (sequence, operations, scheme, signer, signature; base64 bytes). Its STORAGE HASH is SHA-256("infrix:did-storage-entry:v1\x00" || the entry's
// bytes), the hash the next entry names as its predecessor.
//
// THE CHAIN: the first entry is a genesis (version "1", sequence 1, no predecessor, no operation, not deactivated); every later entry names the exact storage hash of the entry before
// it, has the next sequence and version, carries at least one operation, deactivate alone and reactivate first (lifecycle.go: a reactivation proves the commitment of the
// deactivation it undoes), no change of a deactivated subject but a reactivation, no
// reactivation of an active one, and the deactivated state its operations yield. THE AUTHORITY: an anon statement is an Ed25519 signature of the digest by an authentication key
// (Multikey) of the PREVIOUS document (the genesis by its own); a chain statement is the DID's foreign account's signature of the statement message in its chain's standard.
//
// THE DOCUMENTS: every later version's document is re-derived from the document before it by applying its statement's operations (derive.go), and its canonical hash must be the
// hash the entry binds, so an authentic chain over a document the operations do not yield is refused. derive.go states the one thing core checks beyond this (the document rules).
package didchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// Domains and names of the statement chain.
const (
	StatementDomain      = "infrix:did-statement:v1\x00"
	StorageDomain        = "infrix:did-storage-entry:v1\x00"
	HashAlgorithm        = "sha-256/jcs-rfc8785"
	StorageFormatVersion = 2
	SchemeEd25519        = "ed25519"
	OperationDeactivate  = "deactivate"
	OperationReactivate  = "reactivate"
)

// The refusals: a history that is not a chain of authorized statements (the vectors' "statement-chain-refused"), and an entry that is not a registry entry of the DID and its account
// ("anon-history-refused").
var (
	ErrStatementChain = errors.New("statement chain refused")
	ErrEntry          = errors.New("registry entry refused")
)

// Operation is a statement operation as the entry stores it: its type and its JSON object.
type Operation struct {
	Type   string
	Object map[string]json.RawMessage
}

// Entry is one entry of a history, read from its bytes.
type Entry struct {
	DID, NetworkID, AccountURL, VersionID string
	Sequence                              uint64
	PredecessorStorageHash                []byte
	Operations                            []Operation
	DocumentHash, StorageHash             []byte
	Deactivated                           bool
	// Created and Updated are the times the entry's metadata states (held to the ledger's when the history carries its ledger times: lifecycle.go)
	Created, Updated  time.Time
	Document          json.RawMessage
	Scheme            string
	Signer, Signature []byte
}

func lp(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// Digest is the statement digest of an entry. An operation whose members have no canonical form is an error.
func Digest(e *Entry) ([32]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(StatementDomain))
	lp(h, []byte(e.DID))
	lp(h, []byte(e.NetworkID))
	lp(h, []byte(e.VersionID))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], e.Sequence)
	_, _ = h.Write(n[:])
	lp(h, e.PredecessorStorageHash)
	binary.BigEndian.PutUint64(n[:], uint64(len(e.Operations)))
	_, _ = h.Write(n[:])
	for i, op := range e.Operations {
		members := map[string]json.RawMessage{}
		for name, value := range op.Object {
			if name != "type" {
				members[name] = value
			}
		}
		// the members are raw JSON values of a decoded object, so they marshal; the canonical form may still refuse a number or a duplicate
		text, _ := json.Marshal(members)
		canonical, err := CanonicalizeJSON(text)
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: operation %d (%s) has no canonical form: %v", ErrStatementChain, i, op.Type, err)
		}
		lp(h, []byte(op.Type))
		lp(h, canonical)
	}
	lp(h, e.DocumentHash)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// StorageHash is the storage hash of an entry's bytes.
func StorageHash(raw []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(StorageDomain))
	_, _ = h.Write(raw)
	return h.Sum(nil)
}

// DocumentHash is SHA-256 of the canonical form of a document's JSON.
func DocumentHash(document []byte) ([]byte, error) {
	canonical, err := CanonicalizeJSON(document)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

func entryRefuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEntry, fmt.Sprintf(format, args...))
}

// strictObject decodes a JSON object whose members must be among allowed, refusing a duplicate member (I-JSON) and any other member.
func strictObject(raw json.RawMessage, what string, allowed ...string) (map[string]json.RawMessage, error) {
	if _, err := CanonicalizeJSON(raw); err != nil {
		return nil, entryRefuse("%s is not I-JSON: %v", what, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, entryRefuse("%s is not a JSON object", what)
	}
	if allowed != nil {
		set := map[string]bool{}
		for _, name := range allowed {
			set[name] = true
		}
		for name := range members {
			if !set[name] {
				return nil, entryRefuse("%s carries the member %q, which it does not define", what, name)
			}
		}
	}
	return members, nil
}

func decodeBytes(raw json.RawMessage, what string) ([]byte, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, entryRefuse("%s is not a base64 string", what)
	}
	out, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, entryRefuse("%s is not base64: %v", what, err)
	}
	return out, nil
}

func decodeString(raw json.RawMessage, what string) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", entryRefuse("%s is not a string", what)
	}
	return text, nil
}

// DecodeEntry reads one registry entry's bytes: the v2 envelope of the canonical hash, its document hashed as stored, its bindings and its statement.
func DecodeEntry(raw []byte) (*Entry, error) {
	top, err := strictObject(raw, "the entry", "document", "metadata", "hash", "hashAlgorithm", "version", "identity", "predecessor", "migration", "statement")
	if err != nil {
		return nil, err
	}
	for _, required := range []string{"document", "metadata", "hash", "hashAlgorithm", "version", "identity", "statement"} {
		if _, ok := top[required]; !ok {
			return nil, entryRefuse("the entry carries no %s", required)
		}
	}
	if _, ok := top["migration"]; ok {
		return nil, entryRefuse("a registry entry carries no migration evidence")
	}
	if string(top["version"]) != strconv.Itoa(StorageFormatVersion) {
		return nil, entryRefuse("the entry is version %s, want %d", top["version"], StorageFormatVersion)
	}
	if algorithm, err := decodeString(top["hashAlgorithm"], "hashAlgorithm"); err != nil || algorithm != HashAlgorithm {
		return nil, entryRefuse("the entry's hash algorithm is %s, want %s", top["hashAlgorithm"], HashAlgorithm)
	}
	e := &Entry{Document: top["document"], StorageHash: StorageHash(raw)}
	if e.DocumentHash, err = decodeBytes(top["hash"], "hash"); err != nil {
		return nil, err
	}
	if actual, err := DocumentHash(top["document"]); err != nil || !bytes.Equal(actual, e.DocumentHash) {
		return nil, entryRefuse("the stored document hash does not match the document as stored")
	}
	var document struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(top["document"], &document); err != nil {
		return nil, entryRefuse("the document is not a DID document object")
	}
	metadata, err := strictObject(top["metadata"], "the metadata")
	if err != nil {
		return nil, err
	}
	if e.VersionID, err = decodeString(metadata["versionId"], "metadata.versionId"); err != nil || strings.TrimSpace(e.VersionID) == "" {
		return nil, entryRefuse("the metadata carries no version id")
	}
	if value, ok := metadata["deactivated"]; ok {
		if err := json.Unmarshal(value, &e.Deactivated); err != nil {
			return nil, entryRefuse("metadata.deactivated is not a boolean")
		}
	}
	if e.Created, err = decodeTime(metadata["created"], "metadata.created"); err != nil {
		return nil, err
	}
	if e.Updated, err = decodeTime(metadata["updated"], "metadata.updated"); err != nil {
		return nil, err
	}
	identity, err := strictObject(top["identity"], "the identity binding", "canonicalDid", "accountUrl", "networkId", "aliases")
	if err != nil {
		return nil, err
	}
	if e.DID, err = decodeString(identity["canonicalDid"], "identity.canonicalDid"); err != nil {
		return nil, err
	}
	if e.AccountURL, err = decodeString(identity["accountUrl"], "identity.accountUrl"); err != nil {
		return nil, err
	}
	if e.NetworkID, err = decodeString(identity["networkId"], "identity.networkId"); err != nil {
		return nil, err
	}
	if document.ID != e.DID {
		return nil, entryRefuse("the document names %q, the identity binding %q", document.ID, e.DID)
	}
	if raw, ok := top["predecessor"]; ok {
		predecessor, err := strictObject(raw, "the predecessor binding", "versionId", "storageFormatVersion", "documentHash", "storageHash")
		if err != nil {
			return nil, err
		}
		// a member that does not decode reads as empty, which the lengths below refuse, so the decoders' errors decide nothing the lengths do not (part 25i)
		version, _ := decodeString(predecessor["versionId"], "predecessor.versionId")
		documentHash, _ := decodeBytes(predecessor["documentHash"], "predecessor.documentHash")
		storageHash, _ := decodeBytes(predecessor["storageHash"], "predecessor.storageHash")
		if strings.TrimSpace(version) == "" || len(documentHash) != 32 || len(storageHash) != 32 {
			return nil, entryRefuse("the predecessor binding is not a version and two hashes")
		}
		e.PredecessorStorageHash = storageHash
	}
	statement, err := strictObject(top["statement"], "the statement", "sequence", "operations", "scheme", "signer", "signature")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(statement["sequence"], &e.Sequence); err != nil {
		return nil, entryRefuse("statement.sequence is not an unsigned integer")
	}
	if e.Scheme, err = decodeString(statement["scheme"], "statement.scheme"); err != nil {
		return nil, err
	}
	if e.Signer, err = decodeBytes(statement["signer"], "statement.signer"); err != nil {
		return nil, err
	}
	if e.Signature, err = decodeBytes(statement["signature"], "statement.signature"); err != nil {
		return nil, err
	}
	if raw, ok := statement["operations"]; ok {
		var ops []json.RawMessage
		if err := json.Unmarshal(raw, &ops); err != nil {
			return nil, entryRefuse("statement.operations is not an array")
		}
		for i, op := range ops {
			object, err := strictObject(op, fmt.Sprintf("operation %d", i))
			if err != nil {
				return nil, err
			}
			name, err := decodeString(object["type"], fmt.Sprintf("operation %d's type", i))
			if err != nil || name == "" {
				return nil, entryRefuse("operation %d names no type", i)
			}
			e.Operations = append(e.Operations, Operation{Type: name, Object: object})
		}
	}
	return e, nil
}

// Authorizer is a profile's half: the scheme it takes for an entry ("" for none) and whether the authority signed the digest.
type Authorizer interface {
	Scheme(e *Entry) string
	Authorize(previous, next *Entry, digest [32]byte) error
}

func chainRefusal(index int, format string, args ...any) error {
	return fmt.Errorf("%w: entry %d: %s", ErrStatementChain, index, fmt.Sprintf(format, args...))
}

// Verify holds a history to the chain rules and to the authorizer, entry by entry.
func Verify(did, networkID string, history []*Entry, authorizer Authorizer) error {
	if len(history) == 0 {
		return fmt.Errorf("%w: the history holds no entry", ErrStatementChain)
	}
	for i, e := range history {
		var previous *Entry
		if i > 0 {
			previous = history[i-1]
		}
		switch {
		case e.DID != did:
			return chainRefusal(i, "the entry names %q, the history is of %q", e.DID, did)
		case e.NetworkID != networkID:
			return chainRefusal(i, "the entry names network %q, the history is of %q", e.NetworkID, networkID)
		case len(e.DocumentHash) == 0:
			return chainRefusal(i, "the statement binds no document")
		}
		if err := verifyShape(i, e, previous); err != nil {
			return err
		}
		if want := authorizer.Scheme(e); want == "" || e.Scheme != want {
			return chainRefusal(i, "the scheme is %q, the authorizer takes %q", e.Scheme, want)
		}
		digest, err := Digest(e)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if err := authorizer.Authorize(previous, e, digest); err != nil {
			return chainRefusal(i, "the signature is not accepted: %v", err)
		}
	}
	return nil
}

func verifyShape(i int, e, previous *Entry) error {
	if previous == nil {
		switch {
		case len(e.PredecessorStorageHash) != 0:
			return chainRefusal(i, "the genesis names a predecessor")
		case len(e.Operations) != 0:
			return chainRefusal(i, "the genesis carries operations")
		case e.Sequence != 1 || e.VersionID != "1":
			return chainRefusal(i, "the genesis is sequence %d version %q, want 1 and 1", e.Sequence, e.VersionID)
		case e.Deactivated:
			return chainRefusal(i, "the genesis is deactivated")
		}
		return nil
	}
	if !bytes.Equal(e.PredecessorStorageHash, previous.StorageHash) {
		return chainRefusal(i, "the entry names predecessor %x, the entry before it is %x", e.PredecessorStorageHash, previous.StorageHash)
	}
	if e.Sequence != previous.Sequence+1 {
		return chainRefusal(i, "sequence %d after %d", e.Sequence, previous.Sequence)
	}
	if want := strconv.FormatUint(previous.Sequence+1, 10); e.VersionID != want {
		return chainRefusal(i, "version %q, want %q", e.VersionID, want)
	}
	if len(e.Operations) == 0 {
		return chainRefusal(i, "an update carries no operation")
	}
	deactivates, reactivates, err := checkPlacement(i, e.Operations)
	if err != nil {
		return err
	}
	if previous.Deactivated && !reactivates {
		return chainRefusal(i, "the subject is deactivated and only a reactivation changes it")
	}
	if reactivates && !previous.Deactivated {
		return chainRefusal(i, "a reactivation of a subject that is active")
	}
	if err := verifyLifecycle(i, e, previous, deactivates, reactivates); err != nil {
		return err
	}
	want := (previous.Deactivated || deactivates) && !reactivates
	if e.Deactivated != want {
		return chainRefusal(i, "the entry says deactivated=%t and its operations yield deactivated=%t", e.Deactivated, want)
	}
	return nil
}

// ---- the anon profile ----

// AnonAuthorizer authorizes an anon statement: an Ed25519 signature of the digest by an authentication key (a Multikey) of the previous document, the genesis by its own.
type AnonAuthorizer struct{}

// Scheme implements Authorizer.
func (AnonAuthorizer) Scheme(*Entry) string { return SchemeEd25519 }

// Authorize implements Authorizer.
func (AnonAuthorizer) Authorize(previous, next *Entry, digest [32]byte) error {
	authority := next
	if previous != nil {
		authority = previous
	}
	if len(next.Signer) != ed25519.PublicKeySize || len(next.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("the signer is %d bytes and the signature %d, want 32 and 64 (Ed25519)", len(next.Signer), len(next.Signature))
	}
	// the recovery: a reactivation of a committed deactivation is signed by its committed key (verifyShape held it to the commitment), which need not be listed in the deactivated document
	if previous != nil && previous.Deactivated {
		if recovery := recoveryKey(next); !bytes.Equal(recovery, next.Signer) {
			return fmt.Errorf("the reactivation of version %s is signed by %x, and only its committed recovery key %x signs it", previous.VersionID, next.Signer, recovery)
		}
		if !ed25519.Verify(next.Signer, digest[:], next.Signature) {
			return errors.New("the signature does not verify over the statement digest")
		}
		return nil
	}
	keys, err := authenticationKeys(authority.Document)
	if err != nil {
		return fmt.Errorf("the authority document of version %s: %v", authority.VersionID, err)
	}
	listed := false
	for _, key := range keys {
		listed = listed || bytes.Equal(key, next.Signer)
	}
	if !listed {
		return fmt.Errorf("the signer %x is not an authentication key of version %s", next.Signer, authority.VersionID)
	}
	if !ed25519.Verify(next.Signer, digest[:], next.Signature) {
		return errors.New("the signature does not verify over the statement digest")
	}
	return nil
}

// stringOrArray reads a member that is one string or an array of strings (absent is none).
func stringOrArray(raw json.RawMessage) []string {
	// an absent member is empty raw JSON, which neither decode reads: nil
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// authenticationKeys are the Ed25519 keys of a document's authentication relationship: each reference that names a Multikey verification method of the document whose
// publicKeyMultibase is an Ed25519 Multikey ("z" and the base58btc of 0xed 0x01 and the 32-byte key).
func authenticationKeys(document json.RawMessage) ([][]byte, error) {
	var doc struct {
		VerificationMethod []struct {
			ID                 string `json:"id"`
			Type               string `json:"type"`
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		} `json:"verificationMethod"`
		Authentication json.RawMessage `json:"authentication"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("not a DID document: %v", err)
	}
	var keys [][]byte
	for _, ref := range stringOrArray(doc.Authentication) {
		for _, vm := range doc.VerificationMethod {
			if vm.ID != ref || vm.Type != "Multikey" || !strings.HasPrefix(vm.PublicKeyMultibase, "z") {
				continue
			}
			raw := didaccounts.Base58Decode(vm.PublicKeyMultibase[1:])
			if len(raw) == 34 && raw[0] == 0xed && raw[1] == 0x01 {
				keys = append(keys, raw[2:])
			}
		}
	}
	return keys, nil
}

// AnonHistory is the portable form of one anon DID's registry account (core's AnonHistoryFile): the DID, the registry identity, and the base64 entries in ledger order.
type AnonHistory struct {
	DID      string   `json:"did"`
	Registry string   `json:"registry"`
	Entries  []string `json:"entries"`
	// LedgerTimes, when present, are the ledger's record of when each entry landed (lifecycle.go)
	LedgerTimes []string `json:"ledgerTimes,omitempty"`
}

// AnonVerdict is what a verified anon history proves (core's AnonHistoryVerdict, member for member).
type AnonVerdict struct {
	Verified        bool     `json:"verified"`
	DID             string   `json:"did"`
	NetworkID       string   `json:"networkId"`
	Account         string   `json:"account"`
	Entries         int      `json:"entries"`
	TailVersionID   string   `json:"tailVersionId"`
	TailDeactivated bool     `json:"tailDeactivated"`
	TailStorageHash string   `json:"tailStorageHash"`
	Signers         []string `json:"signers"`
	TimesProven     bool     `json:"timesProven"`
	TailLedgerTime  string   `json:"tailLedgerTime,omitempty"`
}

// ParseAnonDID reads did:infrix:v1:anon:<network id>:<subject>, the subject 64 lower-case hexadecimal characters, the network id "g1-" and 64 lower-case hexadecimal characters.
func ParseAnonDID(did string) (network, subject string, err error) {
	parts := strings.Split(did, ":")
	if len(parts) != 6 || parts[0] != "did" || parts[1] != "infrix" || parts[2] != "v1" || parts[3] != "anon" || !isLowerHex(strings.TrimPrefix(parts[4], "g1-"), 64) ||
		!strings.HasPrefix(parts[4], "g1-") || !isLowerHex(parts[5], 64) {
		return "", "", entryRefuse("%q is not a canonical did:infrix:v1:anon DID", did)
	}
	return parts[4], parts[5], nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// VerifyAnonHistory verifies a registry history of an anon or a chain DID as core's VerifyAnonHistoryFile does: every entry decodes as a registry entry of the DID bound to its account
// (<registry>/did-anon-<subject>, or <registry>/did-chain-<digest of the account>), the entries are a chain of statements authorized by the profile's authority (the previous document's
// keys, or the foreign account), and every document is the one its operations yield.
func VerifyAnonHistory(h *AnonHistory) (*AnonVerdict, error) {
	if h == nil || len(h.Entries) == 0 {
		return nil, entryRefuse("the history holds no entries")
	}
	if !strings.HasPrefix(h.Registry, "acc://") || strings.Contains(strings.TrimPrefix(h.Registry, "acc://"), "/") || len(h.Registry) == len("acc://") {
		return nil, entryRefuse("registry %q is not an Accumulate identity URL", h.Registry)
	}
	var network, account string
	var authorizer Authorizer
	if chain, err := ParseChainDID(h.DID); err == nil {
		// a chain DID names no network: the history is held to the network its first entry's identity binding names, and every entry to that one; its account is
		// <registry>/did-chain-<hex SHA-256("infrix:did-chain-registry:v1|" namespace "|" reference "|" account)>
		raw, err := base64.StdEncoding.DecodeString(h.Entries[0])
		if err != nil {
			return nil, entryRefuse("entry 0 is not base64: %v", err)
		}
		var first struct {
			Identity struct {
				NetworkID string `json:"networkId"`
			} `json:"identity"`
		}
		if err := json.Unmarshal(raw, &first); err != nil || !strings.HasPrefix(first.Identity.NetworkID, "g1-") || !isLowerHex(strings.TrimPrefix(first.Identity.NetworkID, "g1-"), 64) {
			return nil, entryRefuse("entry 0 names no network id")
		}
		digest := sha256.Sum256([]byte("infrix:did-chain-registry:v1|" + chain.Namespace + "|" + chain.Reference + "|" + chain.Account))
		network, account, authorizer = first.Identity.NetworkID, h.Registry+"/did-chain-"+hex.EncodeToString(digest[:]), ChainAuthorizer{}
	} else {
		anonNetwork, subject, err := ParseAnonDID(h.DID)
		if err != nil {
			return nil, err
		}
		network, account, authorizer = anonNetwork, h.Registry+"/did-anon-"+subject, AnonAuthorizer{}
	}
	ledger, err := parseLedgerTimes(h.LedgerTimes, len(h.Entries))
	if err != nil {
		return nil, err
	}
	history := make([]*Entry, len(h.Entries))
	for i, encoded := range h.Entries {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, entryRefuse("entry %d is not base64: %v", i, err)
		}
		entry, err := DecodeEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if entry.DID != h.DID || entry.NetworkID != network || entry.AccountURL != account {
			return nil, entryRefuse("entry %d is bound to %s on %s at %s, not to %s on %s at %s", i, entry.DID, entry.NetworkID, entry.AccountURL, h.DID, network, account)
		}
		history[i] = entry
	}
	if err := Verify(h.DID, network, history, authorizer); err != nil {
		return nil, err
	}
	if err := verifyDocuments(history); err != nil {
		return nil, err
	}
	if err := verifyDerivation(history); err != nil {
		return nil, err
	}
	if ledger != nil {
		if err := verifyTimes(history, ledger); err != nil {
			return nil, err
		}
	}
	tail := history[len(history)-1]
	verdict := &AnonVerdict{Verified: true, DID: h.DID, NetworkID: network, Account: account, Entries: len(history), TailVersionID: tail.VersionID, TailDeactivated: tail.Deactivated,
		TailStorageHash: hex.EncodeToString(tail.StorageHash), TimesProven: ledger != nil}
	if ledger != nil {
		verdict.TailLedgerTime = ledger[len(ledger)-1].Format(time.RFC3339)
	}
	seen := map[string]bool{}
	for _, e := range history {
		if signer := hex.EncodeToString(e.Signer); !seen[signer] {
			seen[signer] = true
			verdict.Signers = append(verdict.Signers, signer)
		}
	}
	return verdict, nil
}

// ---- the chain profile ----

// ChainAuthorizer authorizes a chain statement: every statement, the genesis included, is the DID's foreign account's signature of the statement message, by its namespace's verifier.
type ChainAuthorizer struct{}

// Scheme implements Authorizer.
func (ChainAuthorizer) Scheme(e *Entry) string {
	account, err := ParseChainDID(e.DID)
	if err != nil {
		return ""
	}
	return chainVerifiers[account.Namespace].Scheme()
}

// Authorize implements Authorizer.
func (ChainAuthorizer) Authorize(_, next *Entry, digest [32]byte) error {
	account, err := ParseChainDID(next.DID)
	if err != nil {
		return err
	}
	return chainVerifiers[account.Namespace].Verify(account, ChainStatementMessage(digest), next.Signer, next.Signature)
}
