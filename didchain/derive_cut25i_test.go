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
	"reflect"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// Part 25i, the cut of didchain/derive.go: every refusal of the derivation is held by its own words, and every document it yields by its exact members.

const cutBaseDID = "did:infrix:v1:anon:x"

func cutKey(label string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, "z" + didaccounts.Base58Encode(append([]byte{0xed, 0x01}, pub...))
}

// cutBase is a document of one Ed25519 Multikey method (authentication) and one service, with edits applied.
func cutBase(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	_, _, mb := cutKey("infrix-key")
	doc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/did/v1"}, "id": cutBaseDID, "controller": cutBaseDID,
		"verificationMethod": []any{map[string]any{"id": cutBaseDID + "#k1", "type": "Multikey", "controller": cutBaseDID, "publicKeyMultibase": mb}},
		"authentication":     cutBaseDID + "#k1",
		"service":            []any{map[string]any{"id": cutBaseDID + "#s", "type": "LinkedDomains", "serviceEndpoint": "https://a.example"}},
	}
	if edit != nil {
		edit(doc)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cutOp(t *testing.T, text string) Operation {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &members); err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	var typ string
	_ = json.Unmarshal(members["type"], &typ)
	return Operation{Type: typ, Object: members}
}

func TestEveryRefusalOfTheDerivationIsHeldByItsOwnWords(t *testing.T) {
	notArray := func(name string) func(map[string]any) { return func(d map[string]any) { d[name] = "x" } }
	number := func(name string) func(map[string]any) { return func(d map[string]any) { d[name] = 7 } }
	vm := func(extra string) string {
		return `{"type":"addVerificationMethod","verificationMethod":{"id":"` + cutBaseDID + `#k2","type":"Multikey","controller":"` + cutBaseDID + `"` + extra + `}}`
	}
	for _, c := range []struct {
		name  string
		edit  func(map[string]any)
		op    string
		words string
	}{
		{"methods that are no array", notArray("verificationMethod"), vm(""), "the member verificationMethod is not an array"},
		{"a method with a member it does not define", nil, vm(`,"extra":"x"`), `carries the member "extra"`},
		{"a method of no type", nil, `{"type":"addVerificationMethod","verificationMethod":{"id":"` + cutBaseDID + `#k2","controller":"` + cutBaseDID + `"}}`, "id, type and controller are required"},
		{"a method of no controller", nil, `{"type":"addVerificationMethod","verificationMethod":{"id":"` + cutBaseDID + `#k2","type":"Multikey"}}`, "id, type and controller are required"},
		{"a method of no id", nil, `{"type":"addVerificationMethod","verificationMethod":{"type":"Multikey","controller":"` + cutBaseDID + `"}}`, "id, type and controller are required"},
		{"a threshold that is no integer literal", nil, vm(`,"threshold":2.0`), "is not an integer literal"},
		{"a negative threshold", nil, vm(`,"threshold":-1`), "is not an integer in its range"},
		{"a JWK with a member it does not define", nil, vm(`,"publicKeyJwk":{"kty":"OKP","extra":"x"}`), `carries the member "extra"`},
		{"a relationship list that is no list", number("assertionMethod"), `{"type":"addVerificationMethod","relationships":["assertionMethod"],"verificationMethod":{"id":"` + cutBaseDID + `#k2","type":"Multikey","controller":"` + cutBaseDID + `"}}`, "assertionMethod is neither a string nor an array"},
		{"remove a method of no id", nil, `{"type":"removeVerificationMethod"}`, `the member "verificationMethodId" is required`},
		{"remove a method named null", nil, `{"type":"removeVerificationMethod","verificationMethodId":null}`, `the member "verificationMethodId" is required`},
		{"remove from methods that are no array", notArray("verificationMethod"), `{"type":"removeVerificationMethod","verificationMethodId":"` + cutBaseDID + `#k1"}`, "the member verificationMethod is not an array"},
		{"remove from a relationship that is no list", number("keyAgreement"), `{"type":"removeVerificationMethod","verificationMethodId":"` + cutBaseDID + `#k1"}`, "keyAgreement is neither a string nor an array"},
		{"update a method of no id", nil, `{"type":"updateVerificationMethod","updates":{"threshold":2}}`, `the member "verificationMethodId" is required`},
		{"update with no updates", nil, `{"type":"updateVerificationMethod","verificationMethodId":"` + cutBaseDID + `#k1","updates":{}}`, "no updates specified"},
		{"update methods that are no array", notArray("verificationMethod"), `{"type":"updateVerificationMethod","verificationMethodId":"` + cutBaseDID + `#k1","updates":{"threshold":2}}`, "the member verificationMethod is not an array"},
		{"add a service with a member it does not define", nil, `{"type":"addService","service":{"id":"` + cutBaseDID + `#s2","type":"T","serviceEndpoint":"https://b","extra":1}}`, `carries the member "extra"`},
		{"add a service of no type", nil, `{"type":"addService","service":{"id":"` + cutBaseDID + `#s2","serviceEndpoint":"https://b"}}`, "id, type and endpoint are required"},
		{"add a service of no endpoint", nil, `{"type":"addService","service":{"id":"` + cutBaseDID + `#s2","type":"T"}}`, "id, type and endpoint are required"},
		{"add to services that are no array", notArray("service"), `{"type":"addService","service":{"id":"` + cutBaseDID + `#s2","type":"T","serviceEndpoint":"https://b"}}`, "the member service is not an array"},
		{"remove a service of no id", nil, `{"type":"removeService"}`, `the member "serviceId" is required`},
		{"remove from services that are no array", notArray("service"), `{"type":"removeService","serviceId":"` + cutBaseDID + `#s"}`, "the member service is not an array"},
		{"add a controller of no DID", nil, `{"type":"addController"}`, `the member "controllerDid" is required`},
		{"add to controllers that are no list", number("controller"), `{"type":"addController","controllerDid":"did:y"}`, "controller is neither a string nor an array"},
		{"add an alias of no identifier", nil, `{"type":"addAlsoKnownAs"}`, `the member "identifier" is required`},
		{"add to aliases that are no list", number("alsoKnownAs"), `{"type":"addAlsoKnownAs","identifier":"https://x"}`, "alsoKnownAs is neither a string nor an array"},
		{"add a relationship of no name", nil, `{"type":"addRelationship","verificationMethodId":"` + cutBaseDID + `#k1"}`, `the member "relationship" is required`},
		{"add a relationship of no method", nil, `{"type":"addRelationship","relationship":"assertionMethod"}`, `the member "verificationMethodId" is required`},
		{"add a relationship over methods that are no array", notArray("verificationMethod"), `{"type":"addRelationship","relationship":"assertionMethod","verificationMethodId":"` + cutBaseDID + `#k1"}`, "the member verificationMethod is not an array"},
		{"add to a relationship that is no list", number("assertionMethod"), `{"type":"addRelationship","relationship":"assertionMethod","verificationMethodId":"` + cutBaseDID + `#k1"}`, "assertionMethod is neither a string nor an array"},
		{"a foreign alias with no binding", nil, `{"type":"addAlsoKnownAs","identifier":"did:key:z6Mkx"}`, "needs a verified binding"},
	} {
		_, err := DeriveDocument(cutBase(t, c.edit), []Operation{cutOp(t, c.op)})
		if !errors.Is(err, ErrDerivation) || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want a refusal saying %q, got %v", c.name, c.words, err)
		}
	}
	if _, err := DeriveDocument([]byte("not json"), nil); err == nil || !strings.Contains(err.Error(), "the document is not JSON") {
		t.Errorf("a document that is not JSON: %v", err)
	}
	if _, err := DerivedDocumentHash(map[string]any{"x": make(chan int)}); !errors.Is(err, ErrDerivation) || !strings.Contains(err.Error(), "the derived document does not encode") {
		t.Errorf("a document that does not encode: %v", err)
	}
}

func TestEveryDocumentTheDerivationYieldsHasExactlyItsMembers(t *testing.T) {
	derive := func(edit func(map[string]any), ops ...string) map[string]any {
		t.Helper()
		var list []Operation
		for _, o := range ops {
			list = append(list, cutOp(t, o))
		}
		doc, err := DeriveDocument(cutBase(t, edit), list)
		if err != nil {
			t.Fatalf("%v: %v", ops, err)
		}
		return doc
	}
	member := func(doc map[string]any, list string, i int) map[string]any {
		return doc[list].([]any)[i].(map[string]any)
	}
	// the edges of the integer ranges, a null string member skipped, a negative signed priority, an empty list member omitted
	doc := derive(nil, `{"type":"addVerificationMethod","verificationMethod":{"id":"`+cutBaseDID+`#k2","type":"Multikey","controller":"`+cutBaseDID+`","threshold":18446744073709549568,"keyPageUrl":null}}`,
		`{"type":"addService","service":{"id":"`+cutBaseDID+`#s2","type":"T","serviceEndpoint":"https://b","priority":-1,"routingKeys":[]}}`,
		`{"type":"addService","service":{"id":"`+cutBaseDID+`#s3","type":"T","serviceEndpoint":"https://c","priority":9223372036854774784}}`)
	if vm := member(doc, "verificationMethod", 1); vm["threshold"] != json.Number("18446744073709549568") || vm["keyPageUrl"] != nil {
		t.Errorf("the method at the unsigned edge: %v", vm)
	}
	if svc := member(doc, "service", 1); svc["priority"] != json.Number("-1") || svc["routingKeys"] != nil {
		t.Errorf("the service with a negative priority and no routing key: %v", svc)
	}
	if _, present := member(doc, "service", 1)["routingKeys"]; present {
		t.Error("an empty routingKeys is carried")
	}
	if svc := member(doc, "service", 2); svc["priority"] != json.Number("9223372036854774784") {
		t.Errorf("the service at the signed edge: %v", svc)
	}
	// an update reads numbers as an entry stores them (2.0 is 2), and an empty required member is written empty
	doc = derive(nil, `{"type":"updateVerificationMethod","verificationMethodId":"`+cutBaseDID+`#k1","updates":{"threshold":2.0,"controller":""}}`)
	if vm := member(doc, "verificationMethod", 0); vm["threshold"] != json.Number("2") || vm["controller"] != "" {
		t.Errorf("the updated method: %v", vm)
	}
	// one controller is a string, one alias an array, one relationship left a string; a relationship is removed from a method that does not exist
	doc = derive(func(d map[string]any) { delete(d, "controller") }, `{"type":"addController","controllerDid":"did:y"}`)
	if doc["controller"] != "did:y" {
		t.Errorf("one controller: %#v", doc["controller"])
	}
	doc = derive(nil, `{"type":"addAlsoKnownAs","identifier":"https://x","foreign":{}}`)
	if !reflect.DeepEqual(doc["alsoKnownAs"], []any{"https://x"}) {
		t.Errorf("one alias: %#v", doc["alsoKnownAs"])
	}
	doc = derive(func(d map[string]any) { d["alsoKnownAs"] = []any{"https://x", "https://y"} }, `{"type":"removeAlsoKnownAs","identifier":"https://x"}`)
	if !reflect.DeepEqual(doc["alsoKnownAs"], []any{"https://y"}) {
		t.Errorf("one alias left: %#v", doc["alsoKnownAs"])
	}
	doc = derive(func(d map[string]any) { d["assertionMethod"] = []any{cutBaseDID + "#k1", cutBaseDID + "#k9"} }, `{"type":"removeRelationship","relationship":"assertionMethod","verificationMethodId":"`+cutBaseDID+`#k9"}`)
	if doc["assertionMethod"] != cutBaseDID+"#k1" {
		t.Errorf("one relationship left: %#v", doc["assertionMethod"])
	}
}

// cutBinding is a did:key binding of the base document, both sides signed, with edits applied after signing.
func cutBinding(t *testing.T, nonce string, edit func(map[string]any)) string {
	t.Helper()
	pub, priv, mb := cutKey("foreign-key")
	_ = pub
	_, ipriv, _ := cutKey("infrix-key")
	foreign := "did:key:" + mb
	statement := []byte("infrix-alias-binding/v1\n" + cutBaseDID + "\n" + foreign + "\n" + nonce)
	b := map[string]any{"infrixDid": cutBaseDID, "foreignDid": foreign, "nonce": nonce, "infrixKeyId": cutBaseDID + "#k1", "foreignKeyId": foreign + "#" + mb,
		"foreignProofValue": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, statement)), "infrixProofValue": base64.StdEncoding.EncodeToString(ed25519.Sign(ipriv, statement))}
	if edit != nil {
		edit(b)
	}
	raw, _ := json.Marshal(map[string]any{"type": "addAlsoKnownAs", "identifier": b["foreignDid"], "binding": b})
	return string(raw)
}

func TestEveryRefusalOfAStoredBindingIsHeldByItsOwnWords(t *testing.T) {
	apply := func(op string, edit func(map[string]any)) error {
		_, err := DeriveDocument(cutBase(t, edit), []Operation{cutOp(t, op)})
		return err
	}
	good := strings.Repeat("n", 16)
	if err := apply(cutBinding(t, good, nil), nil); err != nil {
		t.Fatalf("a binding of a sixteen-character nonce, both sides signed: %v", err)
	}
	_, _, mb := cutKey("foreign-key")
	foreign := "did:key:" + mb
	for name, c := range map[string]struct {
		op    string
		edit  func(map[string]any)
		words string
	}{
		"a binding of another alias":               {strings.Replace(cutBinding(t, good, nil), `"identifier":"`+foreign, `"identifier":"did:key:zOther`, 1), nil, "the binding names"},
		"a fifteen-character nonce":                {cutBinding(t, good[:15], nil), nil, "nonce is shorter than 16 characters"},
		"a signer that is no base64":               {cutBinding(t, good, func(b map[string]any) { b["foreignSigner"] = "%%%" }), nil, "is not base64"},
		"a proof that is no base64":                {cutBinding(t, good, func(b map[string]any) { b["foreignProofValue"] = "%%%" }), nil, "is not base64"},
		"a foreign key of another id":              {cutBinding(t, good, func(b map[string]any) { b["foreignKeyId"] = foreign + "#k" }), nil, "the foreign key is not the did:key's own key"},
		"a forged foreign proof":                   {cutBinding(t, good, func(b map[string]any) { b["foreignProofValue"] = base64.StdEncoding.EncodeToString(make([]byte, 64)) }), nil, "the foreign controller's signature does not verify"},
		"a forged Infrix proof":                    {cutBinding(t, good, func(b map[string]any) { b["infrixProofValue"] = base64.StdEncoding.EncodeToString(make([]byte, 64)) }), nil, "the Infrix controller's signature does not verify"},
		"an Infrix proof of no base64":             {cutBinding(t, good, func(b map[string]any) { b["infrixProofValue"] = "%%%" }), nil, "the Infrix controller's signature does not verify"},
		"an Infrix key that does not authenticate": {cutBinding(t, good, nil), func(d map[string]any) { d["authentication"] = cutBaseDID + "#other" }, "the Infrix controller's signature does not verify"},
		"an Infrix key of no Multikey": {cutBinding(t, good, nil), func(d map[string]any) {
			_, _, imb := cutKey("infrix-key") // the Infrix key itself, spelled in another base: only the base refuses it
			d["verificationMethod"].([]any)[0].(map[string]any)["publicKeyMultibase"] = "u" + strings.TrimPrefix(imb, "z")
		}, "the Infrix controller's signature does not verify"},
		"an Infrix key of another codec": {cutBinding(t, good, nil), func(d map[string]any) {
			pub, _, _ := cutKey("infrix-key")
			d["verificationMethod"].([]any)[0].(map[string]any)["publicKeyMultibase"] = "z" + didaccounts.Base58Encode(append([]byte{0xec, 0x01}, pub...))
		}, "the Infrix controller's signature does not verify"},
		"a did:key spelled in another base": {strings.ReplaceAll(cutBinding(t, good, nil), foreign, "did:key:x"+strings.TrimPrefix(mb, "z")), nil, "is not an Ed25519 Multikey"},
		"a did:key of another codec":        {strings.ReplaceAll(cutBinding(t, good, nil), foreign, "did:key:z"+didaccounts.Base58Encode(append([]byte{0xec, 0x01}, make([]byte, 32)...))), nil, "is not an Ed25519 Multikey"},
		"a did:pkh of four parts": {cutBinding(t, good, func(b map[string]any) {
			b["foreignDid"] = "did:pkh:eip155:1:0x52908400098527886e0f7030069857d2e4169ee7:x"
		}), nil, "is not namespace:reference:account (CAIP-10)"},
		"a did:pkh of no account": {cutBinding(t, good, func(b map[string]any) { b["foreignDid"] = "did:pkh:eip155:1:0x12" }), nil, "does not name an account of a supported namespace"},
	} {
		if err := apply(c.op, c.edit); !errors.Is(err, ErrDerivation) || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want a refusal saying %q, got %v", name, c.words, err)
		}
	}
}

func TestAHistoryWhoseOperationsDoNotApplyIsRefusedForThatReason(t *testing.T) {
	history := []*Entry{{Document: cutBase(t, nil), VersionID: "1"}, {Operations: []Operation{cutOp(t, `{"type":"removeService","serviceId":"`+cutBaseDID+`#none"}`)}}}
	err := verifyDerivation(history)
	if !errors.Is(err, ErrStatementChain) || !strings.Contains(err.Error(), "the statement's operations do not apply to version 1") {
		t.Fatalf("want the refusal of operations that do not apply, got %v", err)
	}
}

func TestTheInfrixKeyOfAStoredBindingIsTheMethodItNames(t *testing.T) {
	// two Ed25519 methods; the binding names the second, which authenticates and signed it: the first is not read for it
	_, ipriv2, mb2 := cutKey("infrix-key-2")
	edit := func(d map[string]any) {
		d["verificationMethod"] = append(d["verificationMethod"].([]any), map[string]any{"id": cutBaseDID + "#k2", "type": "Multikey", "controller": cutBaseDID, "publicKeyMultibase": mb2})
		d["authentication"] = []any{cutBaseDID + "#k1", cutBaseDID + "#k2"}
	}
	nonce := strings.Repeat("n", 16)
	_, _, fmb := cutKey("foreign-key")
	statement := []byte("infrix-alias-binding/v1\n" + cutBaseDID + "\ndid:key:" + fmb + "\n" + nonce)
	op := cutBinding(t, nonce, func(b map[string]any) {
		b["infrixKeyId"] = cutBaseDID + "#k2"
		b["infrixProofValue"] = base64.StdEncoding.EncodeToString(ed25519.Sign(ipriv2, statement))
	})
	if _, err := DeriveDocument(cutBase(t, edit), []Operation{cutOp(t, op)}); err != nil {
		t.Fatalf("a binding the second method signed: %v", err)
	}
}
