// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// THE SHARED VECTORS (infrix core part 25g, row H3). The vector file is the one credverify pins (credverify/testdata/did-vectors-v1.json, the exact output of `infrix did vectors --out`
// in infrix core, generated, never retyped). This package is held to its canonicalJson, chainSignatures and anonHistory sections and to the chain-profile parse vectors.

type vectorFile struct {
	Parse []struct {
		Name    string `json:"name"`
		Input   string `json:"input"`
		Valid   bool   `json:"valid"`
		Profile string `json:"profile"`
	} `json:"parse"`
	CanonicalJSON []struct {
		Name, Input, Canonical, SHA256, Refusal string
		Valid                                   bool
	} `json:"canonicalJson"`
	ChainSignatures []struct {
		Name         string `json:"name"`
		DID          string `json:"did"`
		Scheme       string `json:"scheme"`
		MessageHex   string `json:"messageHex"`
		SignerHex    string `json:"signerHex"`
		SignatureHex string `json:"signatureHex"`
		Valid        bool   `json:"valid"`
	} `json:"chainSignatures"`
	AnonHistory []struct {
		Name    string       `json:"name"`
		Valid   bool         `json:"valid"`
		Refusal string       `json:"refusal"`
		Verdict *AnonVerdict `json:"verdict"`
		History AnonHistory  `json:"history"`
	} `json:"anonHistory"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../credverify/testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.CanonicalJSON) == 0 || len(v.ChainSignatures) == 0 || len(v.AnonHistory) == 0 {
		t.Fatalf("the vector file carries %d canonical-json, %d chain-signature and %d anon-history vectors: every section is needed", len(v.CanonicalJSON), len(v.ChainSignatures), len(v.AnonHistory))
	}
	return v
}

func TestEveryCanonicalJSONVectorIsReproduced(t *testing.T) {
	for _, v := range loadVectors(t).CanonicalJSON {
		got, err := CanonicalizeJSON([]byte(v.Input))
		switch {
		case v.Valid && (err != nil || string(got) != v.Canonical):
			t.Errorf("%s: %s (%v), want %s", v.Name, got, err, v.Canonical)
		case v.Valid:
			if sum, _ := DocumentHash([]byte(v.Input)); hex.EncodeToString(sum) != v.SHA256 {
				t.Errorf("%s: sha256 %x, want %s", v.Name, sum, v.SHA256)
			}
		case CanonicalRefusal(err) != v.Refusal:
			t.Errorf("%s: refused as %q (%v), want %q", v.Name, CanonicalRefusal(err), err, v.Refusal)
		}
	}
}

func TestEveryChainSignatureVectorReachesItsVerdict(t *testing.T) {
	valid := map[string]bool{}
	for _, v := range loadVectors(t).ChainSignatures {
		account, err := ParseChainDID(v.DID)
		if err != nil {
			t.Errorf("%s: the DID is refused: %v", v.Name, err)
			continue
		}
		verifier, _ := ChainVerifier(account.Namespace)
		if verifier.Scheme() != v.Scheme {
			t.Errorf("%s: scheme %s, the verifier's is %s", v.Name, v.Scheme, verifier.Scheme())
		}
		message, _ := hex.DecodeString(v.MessageHex)
		signer, _ := hex.DecodeString(v.SignerHex)
		signature, _ := hex.DecodeString(v.SignatureHex)
		err = verifier.Verify(account, message, signer, signature)
		if (err == nil) != v.Valid {
			t.Errorf("%s: verified=%t (%v), want %t", v.Name, err == nil, err, v.Valid)
		}
		if err != nil && !errors.Is(err, ErrChainSignature) {
			t.Errorf("%s: refused outside the chain-signature class: %v", v.Name, err)
		}
		valid[v.Scheme] = valid[v.Scheme] || v.Valid
	}
	for _, scheme := range []string{ChainSchemeBIP122, ChainSchemeCosmos, ChainSchemeEIP155, ChainSchemeSolana} {
		if !valid[scheme] {
			t.Errorf("no valid vector of %s", scheme)
		}
	}
}

func TestEveryChainParseVectorReachesItsVerdict(t *testing.T) {
	seen := 0
	for _, v := range loadVectors(t).Parse {
		if !strings.HasPrefix(v.Input, "did:infrix:v1:chain:") {
			continue
		}
		seen++
		_, err := ParseChainDID(v.Input)
		if (err == nil) != v.Valid {
			t.Errorf("%s: accepted=%t (%v), want %t", v.Name, err == nil, err, v.Valid)
		}
	}
	if seen == 0 {
		t.Fatal("no chain parse vector")
	}
}

func TestEveryAnonHistoryVectorReachesItsVerdict(t *testing.T) {
	classes := map[string]error{"statement-chain-refused": ErrStatementChain, "anon-history-refused": ErrEntry, "reactivation-final": ErrReactivationFinal, "reactivation-key": ErrReactivationKey,
		"reactivation-proof": ErrReactivationProof, "time-after-ledger": ErrTimeAfterLedger, "time-before-predecessor": ErrTimeBeforePredecessor, "created-time": ErrCreatedTime, "ledger-time": ErrLedgerTime}
	valid, refused := 0, 0
	for _, v := range loadVectors(t).AnonHistory {
		history := v.History
		verdict, err := VerifyAnonHistory(&history)
		switch {
		case v.Valid && err != nil:
			t.Errorf("%s: refused: %v", v.Name, err)
		case v.Valid:
			valid++
			if !reflect.DeepEqual(verdict, v.Verdict) {
				t.Errorf("%s: verdict %+v, want %+v", v.Name, verdict, v.Verdict)
			}
		case err == nil:
			t.Errorf("%s: must be refused (%s) and verifies", v.Name, v.Refusal)
		case classes[v.Refusal] == nil || !errors.Is(err, classes[v.Refusal]):
			t.Errorf("%s: refused as %v, want %s", v.Name, err, v.Refusal)
		default:
			refused++
		}
	}
	if valid == 0 || refused == 0 {
		t.Fatalf("%d valid and %d refused anon histories", valid, refused)
	}
}

// TestEveryTamperOfTheValidAnonHistoryIsRefused plants cuts in the valid history beyond the vectors' scenarios: a signature, a signer, the stored document, the stored hash, a stored
// operation, the sequence, the version, the scheme, the identity binding, an envelope member the envelope does not define, a duplicate member, the hash algorithm and the version of the
// envelope: each is refused, by its class.
func TestEveryTamperOfTheValidAnonHistoryIsRefused(t *testing.T) {
	var ok AnonHistory
	for _, v := range loadVectors(t).AnonHistory {
		if v.Valid {
			ok = v.History
		}
	}
	mutate := func(index int, edit func(map[string]any)) AnonHistory {
		raw, _ := base64.StdEncoding.DecodeString(ok.Entries[index])
		var entry map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&entry); err != nil {
			t.Fatal(err)
		}
		edit(entry)
		out, _ := json.Marshal(entry)
		h := ok
		h.Entries = append([]string(nil), ok.Entries...)
		h.Entries[index] = base64.StdEncoding.EncodeToString(out)
		return h
	}
	statement := func(e map[string]any) map[string]any { return e["statement"].(map[string]any) }
	flip := func(b64 string) string {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		raw[0] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	for _, c := range []struct {
		name  string
		h     AnonHistory
		class error
	}{
		{"a changed signature", mutate(2, func(e map[string]any) { statement(e)["signature"] = flip(statement(e)["signature"].(string)) }), ErrStatementChain},
		{"a changed signer", mutate(2, func(e map[string]any) { statement(e)["signer"] = flip(statement(e)["signer"].(string)) }), ErrStatementChain},
		{"a changed document", mutate(1, func(e map[string]any) { e["document"].(map[string]any)["alsoKnownAs"] = []any{"did:web:x"} }), ErrEntry},
		{"a changed document hash", mutate(1, func(e map[string]any) { e["hash"] = flip(e["hash"].(string)) }), ErrEntry},
		{"a changed stored operation", mutate(1, func(e map[string]any) {
			statement(e)["operations"].([]any)[0].(map[string]any)["service"].(map[string]any)["description"] = "x"
		}), ErrStatementChain},
		{"another sequence", mutate(1, func(e map[string]any) { statement(e)["sequence"] = 7 }), ErrStatementChain},
		{"another version", mutate(1, func(e map[string]any) { e["metadata"].(map[string]any)["versionId"] = "9" }), ErrStatementChain},
		{"another scheme", mutate(1, func(e map[string]any) { statement(e)["scheme"] = "secp256k1" }), ErrStatementChain},
		{"another account", mutate(1, func(e map[string]any) {
			e["identity"].(map[string]any)["accountUrl"] = "acc://registry.acme/did-anon-x"
		}), ErrEntry},
		{"a member the envelope does not define", mutate(1, func(e map[string]any) { e["extra"] = true }), ErrEntry},
		{"another hash algorithm", mutate(1, func(e map[string]any) { e["hashAlgorithm"] = "sha-256/infrix-document-json-v1" }), ErrEntry},
		{"another envelope version", mutate(1, func(e map[string]any) { e["version"] = 1 }), ErrEntry},
		{"a deactivated genesis", mutate(0, func(e map[string]any) { e["metadata"].(map[string]any)["deactivated"] = true }), ErrStatementChain},
		{"migration evidence", mutate(1, func(e map[string]any) { e["migration"] = map[string]any{} }), ErrEntry},
	} {
		if _, err := VerifyAnonHistory(&c.h); !errors.Is(err, c.class) {
			t.Errorf("%s: %v, want the class %v", c.name, err, c.class)
		}
	}
	// a duplicate member in an entry's text is refused (I-JSON), never read as its last value
	raw, _ := base64.StdEncoding.DecodeString(ok.Entries[1])
	duplicated := strings.Replace(string(raw), `"version":2`, `"version":2,"version":2`, 1)
	h := ok
	h.Entries = append([]string(nil), ok.Entries...)
	h.Entries[1] = base64.StdEncoding.EncodeToString([]byte(duplicated))
	if _, err := VerifyAnonHistory(&h); !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), "I-JSON") {
		t.Errorf("a duplicate member: %v", err)
	}
	for _, bad := range []AnonHistory{{}, {DID: "did:infrix:v1:anon:x", Registry: ok.Registry, Entries: ok.Entries}, {DID: ok.DID, Registry: "acc://a/b", Entries: ok.Entries}, {DID: ok.DID, Registry: ok.Registry, Entries: []string{"!"}}} {
		if _, err := VerifyAnonHistory(&bad); !errors.Is(err, ErrEntry) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// TestEveryDocumentDerivationVectorIsReproduced applies each case's stored operations to the base document and reaches core's outcome: the canonical document and its hash, or the
// refusal; and the two anon histories whose chain is authentic but whose document is not what the operations yield (underived, misordered) are refused by the derivation.
func TestEveryDocumentDerivationVectorIsReproduced(t *testing.T) {
	raw, err := os.ReadFile("../credverify/testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		DocumentDerivation struct {
			Base  json.RawMessage `json:"base"`
			Cases []struct {
				Name       string            `json:"name"`
				Operations []json.RawMessage `json:"operations"`
				Valid      bool              `json:"valid"`
				Document   string            `json:"document"`
				SHA256     string            `json:"sha256"`
			} `json:"cases"`
		} `json:"documentDerivation"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.DocumentDerivation.Cases) == 0 {
		t.Fatalf("no document-derivation vectors (%v)", err)
	}
	valid, refused := 0, 0
	for _, c := range file.DocumentDerivation.Cases {
		var ops []Operation
		for _, opRaw := range c.Operations {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(opRaw, &object); err != nil {
				t.Fatal(err)
			}
			var name string
			_ = json.Unmarshal(object["type"], &name)
			ops = append(ops, Operation{Type: name, Object: object})
		}
		derived, err := DeriveDocument(file.DocumentDerivation.Base, ops)
		if !c.Valid {
			if !errors.Is(err, ErrDerivation) {
				t.Errorf("%s: must be refused, got %v", c.Name, err)
			}
			refused++
			continue
		}
		if err != nil {
			t.Errorf("%s: refused: %v", c.Name, err)
			continue
		}
		text, _ := json.Marshal(derived)
		canonical, err := CanonicalizeJSON(text)
		if err != nil || string(canonical) != c.Document {
			t.Errorf("%s:\n got %s (%v)\nwant %s", c.Name, canonical, err, c.Document)
		}
		if hash, _ := DerivedDocumentHash(derived); hex.EncodeToString(hash) != c.SHA256 {
			t.Errorf("%s: hash %x, want %s", c.Name, hash, c.SHA256)
		}
		valid++
	}
	if valid == 0 || refused == 0 {
		t.Fatalf("%d valid and %d refused derivation cases", valid, refused)
	}
	for _, v := range loadVectors(t).AnonHistory {
		if strings.HasSuffix(v.Name, "underived") || strings.HasSuffix(v.Name, "misordered") {
			history := v.History
			if _, err := VerifyAnonHistory(&history); !errors.Is(err, ErrDerivation) && !(strings.HasSuffix(v.Name, "misordered") && errors.Is(err, ErrStatementChain) && strings.Contains(err.Error(), "do not apply")) {
				t.Errorf("%s: %v, want the derivation's refusal", v.Name, err)
			}
		}
	}
}

// TestEveryChainHistoryVectorReachesItsVerdict: core's chain-history vectors (an eip155 account's history and its tampered twins) reach their verdicts here, the valid one member for
// member.
func TestEveryChainHistoryVectorReachesItsVerdict(t *testing.T) {
	raw, err := os.ReadFile("../credverify/testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		ChainHistory []struct {
			Name    string       `json:"name"`
			Valid   bool         `json:"valid"`
			Refusal string       `json:"refusal"`
			Verdict *AnonVerdict `json:"verdict"`
			History AnonHistory  `json:"history"`
		} `json:"chainHistory"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.ChainHistory) == 0 {
		t.Fatalf("no chain-history vectors (%v)", err)
	}
	classes := map[string]error{"statement-chain-refused": ErrStatementChain, "anon-history-refused": ErrEntry, "reactivation-final": ErrReactivationFinal, "reactivation-key": ErrReactivationKey,
		"reactivation-proof": ErrReactivationProof, "time-after-ledger": ErrTimeAfterLedger, "time-before-predecessor": ErrTimeBeforePredecessor, "created-time": ErrCreatedTime, "ledger-time": ErrLedgerTime}
	valid, refused := 0, 0
	for _, v := range file.ChainHistory {
		history := v.History
		verdict, err := VerifyAnonHistory(&history)
		switch {
		case v.Valid && (err != nil || !reflect.DeepEqual(verdict, v.Verdict)):
			t.Errorf("%s: %+v %v, want %+v", v.Name, verdict, err, v.Verdict)
		case v.Valid:
			valid++
		case classes[v.Refusal] == nil || !errors.Is(err, classes[v.Refusal]):
			t.Errorf("%s: %v, want %s", v.Name, err, v.Refusal)
		default:
			refused++
		}
	}
	if valid != 1 || refused == 0 {
		t.Fatalf("%d valid and %d refused chain histories", valid, refused)
	}
}

// TestEveryDocumentValidityVectorReachesItsVerdict: each document of core's documentValidity section is admitted or refused by the document rules exactly as core does.
func TestEveryDocumentValidityVectorReachesItsVerdict(t *testing.T) {
	raw, err := os.ReadFile("../credverify/testdata/did-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		DocumentValidity []struct {
			Name     string          `json:"name"`
			Document json.RawMessage `json:"document"`
			Valid    bool            `json:"valid"`
		} `json:"documentValidity"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.DocumentValidity) == 0 {
		t.Fatalf("no document-validity vectors (%v)", err)
	}
	for _, v := range file.DocumentValidity {
		err := CheckDocument(v.Document)
		if (err == nil) != v.Valid {
			t.Errorf("%s: %v, want valid=%t", v.Name, err, v.Valid)
		}
		if err != nil && !errors.Is(err, ErrDocument) {
			t.Errorf("%s: refused outside the document class: %v", v.Name, err)
		}
	}
}
