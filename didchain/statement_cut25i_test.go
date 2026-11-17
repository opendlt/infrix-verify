// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// Part 25i, the cut of didchain/statement.go: every refusal of an entry, a chain's shape, the anon authority and a history is held by its own words.

func cutOKHistory(t *testing.T) AnonHistory {
	t.Helper()
	for _, v := range loadVectors(t).AnonHistory {
		if v.Valid {
			return v.History
		}
	}
	t.Fatal("no valid anon history")
	return AnonHistory{}
}

// cutEntry is entry i of the valid history with an edit of its JSON.
func cutEntry(t *testing.T, i int, edit func(map[string]any)) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(cutOKHistory(t).Entries[i])
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var entry map[string]any
	if err := decoder.Decode(&entry); err != nil {
		t.Fatal(err)
	}
	edit(entry)
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryRefusalOfAnEntryIsHeldByItsOwnWords(t *testing.T) {
	member := func(path ...string) func(map[string]any, any) {
		return func(e map[string]any, v any) {
			m := e
			for _, p := range path[:len(path)-1] {
				m = m[p].(map[string]any)
			}
			m[path[len(path)-1]] = v
		}
	}
	for name, c := range map[string]struct {
		entry int
		edit  func(map[string]any)
		words string
	}{
		"metadata that is no object":           {0, func(e map[string]any) { e["metadata"] = "x" }, "the metadata is not a JSON object"},
		"an empty version id":                  {0, func(e map[string]any) { member("metadata", "versionId")(e, "") }, "the metadata carries no version id"},
		"an identity with a member too many":   {0, func(e map[string]any) { member("identity", "extra")(e, "x") }, `the identity binding carries the member "extra"`},
		"an identity of another DID":           {0, func(e map[string]any) { member("identity", "canonicalDid")(e, "did:infrix:v1:anon:other") }, "the identity binding"},
		"a predecessor with a member too many": {1, func(e map[string]any) { member("predecessor", "extra")(e, "x") }, `the predecessor binding carries the member "extra"`},
		"a predecessor of no version":          {1, func(e map[string]any) { member("predecessor", "versionId")(e, "") }, "the predecessor binding is not a version and two hashes"},
		"a statement with a member too many":   {0, func(e map[string]any) { member("statement", "extra")(e, "x") }, `the statement carries the member "extra"`},
		"a signer that is no base64":           {0, func(e map[string]any) { member("statement", "signer")(e, "%%%") }, "statement.signer is not base64"},
		"an operation that is no object":       {1, func(e map[string]any) { member("statement", "operations")(e, []any{5}) }, "operation 0 is not a JSON object"},
		"an operation of an empty type":        {1, func(e map[string]any) { member("statement", "operations")(e, []any{map[string]any{"type": ""}}) }, "operation 0 names no type"},
	} {
		_, err := DecodeEntry(cutEntry(t, c.entry, c.edit))
		if !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want a refusal saying %q, got %v", name, c.words, err)
		}
	}
	if _, err := strictObject(json.RawMessage("null"), "the thing"); err == nil || !strings.Contains(err.Error(), "the thing is not a JSON object") {
		t.Errorf("null as an object: %v", err)
	}
	if _, err := DocumentHash([]byte("{")); err == nil {
		t.Error("a document that is not JSON has a hash")
	}
	if _, err := Digest(&Entry{Operations: []Operation{{Type: "addService", Object: map[string]json.RawMessage{"n": json.RawMessage("1e400")}}}}); !errors.Is(err, ErrStatementChain) || !strings.Contains(err.Error(), "has no canonical form") {
		t.Errorf("an operation with no canonical form: %v", err)
	}
}

type cutAcceptAll struct{}

func (cutAcceptAll) Scheme(*Entry) string                    { return SchemeEd25519 }
func (cutAcceptAll) Authorize(_, _ *Entry, _ [32]byte) error { return nil }

func TestEveryRefusalOfAChainsShapeIsHeldByItsOwnWords(t *testing.T) {
	genesis := func() *Entry {
		return &Entry{DID: "d", NetworkID: "n", DocumentHash: []byte{1}, Sequence: 1, VersionID: "1", Scheme: SchemeEd25519, StorageHash: []byte{9}}
	}
	next := func(ops ...string) *Entry {
		e := &Entry{DID: "d", NetworkID: "n", DocumentHash: []byte{2}, Sequence: 2, VersionID: "2", Scheme: SchemeEd25519, PredecessorStorageHash: []byte{9}}
		for _, o := range ops {
			e.Operations = append(e.Operations, Operation{Type: o, Object: map[string]json.RawMessage{}})
		}
		return e
	}
	if err := Verify("d", "n", nil, cutAcceptAll{}); !errors.Is(err, ErrStatementChain) || !strings.Contains(err.Error(), "the history holds no entry") {
		t.Errorf("an empty history: %v", err)
	}
	bad := genesis()
	bad.VersionID = "2"
	if err := verifyShape(0, bad, nil); err == nil || !strings.Contains(err.Error(), "want 1 and 1") {
		t.Errorf("a genesis of version 2: %v", err)
	}
	deactivated := genesis()
	deactivated.Deactivated = true
	for name, c := range map[string]struct {
		e, previous *Entry
		words       string
	}{
		"another predecessor":          {func() *Entry { e := next("addService"); e.PredecessorStorageHash = []byte{8}; return e }(), genesis(), "the entry names predecessor"},
		"a sequence that skips":        {func() *Entry { e := next("addService"); e.Sequence = 3; return e }(), genesis(), "sequence 3 after 1"},
		"an update of no operation":    {next(), genesis(), "an update carries no operation"},
		"a lifecycle beside another":   {next(OperationDeactivate, "addService"), genesis(), "deactivate is the only operation of its statement"},
		"an update of a deactivated":   {func() *Entry { e := next("addService"); e.Deactivated = true; return e }(), deactivated, "only a reactivation changes it"},
		"a reactivation of the active": {next(OperationReactivate), genesis(), "a reactivation of a subject that is active"},
		"a deactivation not stated":    {next(OperationDeactivate), genesis(), "deactivated=false and its operations yield deactivated=true"},
	} {
		if err := verifyShape(1, c.e, c.previous); err == nil || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want %q, got %v", name, c.words, err)
		}
	}
	// a scheme the authorizer names none for, and a statement whose digest cannot be made after a valid shape
	if err := Verify("did:web:x", "n", []*Entry{func() *Entry { e := genesis(); e.DID = "did:web:x"; e.Scheme = ""; return e }()}, ChainAuthorizer{}); err == nil || !strings.Contains(err.Error(), "the scheme is") {
		t.Errorf("a DID the chain authorizer names no scheme for: %v", err)
	}
	e1 := next("addService")
	e1.Operations[0].Object["n"] = json.RawMessage("1e400")
	if err := Verify("d", "n", []*Entry{genesis(), e1}, cutAcceptAll{}); err == nil || !strings.Contains(err.Error(), "has no canonical form") {
		t.Errorf("a statement with no digest: %v", err)
	}
}

func TestTheAnonAuthorityAndItsKeysAreHeldExactly(t *testing.T) {
	pub, priv, mb := cutKey("anon-authority")
	doc := func(vmType, multibase string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"id": "d", "verificationMethod": []any{map[string]any{"id": "d#k", "type": vmType, "publicKeyMultibase": multibase}}, "authentication": "d#k"})
		return raw
	}
	if keys, err := authenticationKeys(doc("Multikey", mb)); err != nil || len(keys) != 1 {
		t.Fatalf("the Multikey: %v %v", keys, err)
	}
	for name, d := range map[string]json.RawMessage{
		"a method of another type": doc("Ed25519VerificationKey2020", mb),
		"a key of another codec":   doc("Multikey", "z"+didaccounts.Base58Encode(append([]byte{0xec, 0x01}, pub...))),
		"a key of 33 bytes":        doc("Multikey", "z"+didaccounts.Base58Encode(append([]byte{0xed, 0x01}, pub[:31]...))),
	} {
		if keys, err := authenticationKeys(d); err != nil || len(keys) != 0 {
			t.Errorf("%s: keys %v %v", name, keys, err)
		}
	}
	digest := [32]byte{7}
	signed := &Entry{Document: doc("Multikey", mb), VersionID: "1", Signer: pub, Signature: ed25519.Sign(priv, digest[:])}
	if err := (AnonAuthorizer{}).Authorize(nil, signed, digest); err != nil {
		t.Fatalf("the subject's own signature: %v", err)
	}
	for name, c := range map[string]struct {
		e     *Entry
		words string
	}{
		"a short signer":           {&Entry{Document: signed.Document, Signer: pub[:31], Signature: signed.Signature}, "the signer is 31 bytes and the signature 64"},
		"a short signature":        {&Entry{Document: signed.Document, Signer: pub, Signature: signed.Signature[:63]}, "the signer is 32 bytes and the signature 63"},
		"an authority of no JSON":  {&Entry{Document: json.RawMessage("{"), VersionID: "1", Signer: pub, Signature: signed.Signature}, "the authority document of version 1"},
		"a signature over another": {&Entry{Document: signed.Document, Signer: pub, Signature: ed25519.Sign(priv, []byte("other"))}, "the signature does not verify over the statement digest"},
	} {
		if err := (AnonAuthorizer{}).Authorize(nil, c.e, digest); err == nil || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want %q, got %v", name, c.words, err)
		}
	}
}

func TestAnAnonDIDAndAHistoryAreReadOnlyInTheirCanonicalForm(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	good := "did:infrix:v1:anon:g1-" + hex64 + ":" + hex64
	if _, _, err := ParseAnonDID(good); err != nil {
		t.Fatalf("a canonical anon DID: %v", err)
	}
	for _, d := range []string{
		"did:infrix:v1:anon:g1-" + hex64,
		"did:other:v1:anon:g1-" + hex64 + ":" + hex64,
		"did:infrix:v1:anon:" + hex64 + ":" + hex64,
		"did:infrix:v1:anon:g1-" + hex64 + ":" + hex64[:62],
		"did:infrix:v1:anon:g1-" + hex64 + ":" + strings.ToUpper(hex64),
		"did:infrix:v1:anon:g1-" + hex64[:62] + "zz:" + hex64,
	} {
		if _, _, err := ParseAnonDID(d); err == nil {
			t.Errorf("%s is read", d)
		}
	}
	if !isLowerHex("0a9f", 4) || isLowerHex("0a9", 4) || isLowerHex("0A9f", 4) || isLowerHex("0g9f", 4) || isLowerHex("0/9f", 4) || isLowerHex("0:9f", 4) || isLowerHex("0`9f", 4) {
		t.Error("isLowerHex is not exactly n lower-case hexadecimal digits")
	}
	ok := cutOKHistory(t)
	for name, c := range map[string]struct {
		h     *AnonHistory
		words string
	}{
		"no history":                 {nil, "the history holds no entries"},
		"no entries":                 {&AnonHistory{DID: ok.DID, Registry: ok.Registry}, "the history holds no entries"},
		"a registry of no acc":       {&AnonHistory{DID: ok.DID, Registry: "https://r.acme", Entries: ok.Entries}, "is not an Accumulate identity URL"},
		"a registry with a path":     {&AnonHistory{DID: ok.DID, Registry: "acc://r.acme/x", Entries: ok.Entries}, "is not an Accumulate identity URL"},
		"a registry of no name":      {&AnonHistory{DID: ok.DID, Registry: "acc://", Entries: ok.Entries}, "is not an Accumulate identity URL"},
		"a DID of no profile":        {&AnonHistory{DID: "did:web:x", Registry: ok.Registry, Entries: ok.Entries}, "is not a canonical did:infrix:v1:anon DID"},
		"an entry of no base64":      {&AnonHistory{DID: ok.DID, Registry: ok.Registry, Entries: []string{"%%%"}}, "entry 0 is not base64"},
		"another registry":           {&AnonHistory{DID: ok.DID, Registry: "acc://other.acme", Entries: ok.Entries}, "entry 0 is bound to"},
		"a chain entry of no base64": {&AnonHistory{DID: "did:infrix:v1:chain:eip155:1:0x52908400098527886e0f7030069857d2e4169ee7", Registry: ok.Registry, Entries: []string{"%%%"}}, "entry 0 is not base64"},
		"a chain entry of no network": {&AnonHistory{DID: "did:infrix:v1:chain:eip155:1:0x52908400098527886e0f7030069857d2e4169ee7", Registry: ok.Registry,
			Entries: []string{base64.StdEncoding.EncodeToString([]byte(`{"identity":{}}`))}}, "entry 0 names no network id"},
		"a chain entry whose network lacks its prefix": {&AnonHistory{DID: "did:infrix:v1:chain:eip155:1:0x52908400098527886e0f7030069857d2e4169ee7", Registry: ok.Registry,
			Entries: []string{base64.StdEncoding.EncodeToString([]byte(`{"identity":{"networkId":"` + hex64 + `"}}`))}}, "entry 0 names no network id"},
		"an entry bound to another network only": {&AnonHistory{DID: ok.DID, Registry: ok.Registry, Entries: []string{base64.StdEncoding.EncodeToString(cutEntry(t, 0, func(e map[string]any) {
			e["identity"].(map[string]any)["networkId"] = "g1-" + strings.Repeat("cd", 32)
		}))}}, "entry 0 is bound to"},
	} {
		if _, err := VerifyAnonHistory(c.h); err == nil || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want %q, got %v", name, c.words, err)
		}
	}
}
