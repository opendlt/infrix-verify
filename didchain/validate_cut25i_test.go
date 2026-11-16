// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// Part 25i, the cut of didchain/validate.go: every refusal of the document rules is held by its own words, and every endpoint the DIDComm rule admits is admitted.

func TestEveryRefusalOfTheDocumentRulesIsHeldByItsOwnWords(t *testing.T) {
	if err := CheckDocument(cutBase(t, nil)); err != nil {
		t.Fatalf("the base document: %v", err)
	}
	pub, _, _ := cutKey("infrix-key")
	vm0 := func(d map[string]any) map[string]any { return d["verificationMethod"].([]any)[0].(map[string]any) }
	svc0 := func(d map[string]any) map[string]any { return d["service"].([]any)[0].(map[string]any) }
	proof := func(created string) func(map[string]any) {
		return func(d map[string]any) {
			d["proof"] = map[string]any{"type": "Ed25519Signature2020", "created": created, "verificationMethod": cutBaseDID + "#k1", "proofPurpose": "assertionMethod"}
		}
	}
	for name, c := range map[string]struct {
		edit  func(map[string]any)
		words string
	}{
		"a null context":                  {func(d map[string]any) { d["@context"] = nil }, "missing W3C DID context"},
		"an id that is a number":          {func(d map[string]any) { d["id"] = 5 }, "id is not a string"},
		"a null id":                       {func(d map[string]any) { d["id"] = nil }, "the document is not in its model's form"},
		"a controller that is a number":   {func(d map[string]any) { d["controller"] = 5 }, "controller is neither a string nor an array"},
		"a null alias list":               {func(d map[string]any) { d["alsoKnownAs"] = nil }, "the document is not in its model's form"},
		"an alias that is a number":       {func(d map[string]any) { d["alsoKnownAs"] = []any{5} }, "alsoKnownAs holds a value that is not a string"},
		"a null method list":              {func(d map[string]any) { d["verificationMethod"] = nil }, "the document is not in its model's form"},
		"a method with a member it lacks": {func(d map[string]any) { vm0(d)["extra"] = "x" }, `carries the member "extra"`},
		"a null proof":                    {func(d map[string]any) { d["proof"] = nil }, "the document is not in its model's form"},
		"a proof with a member it lacks":  {func(d map[string]any) { proof("2026-11-16T10:00:00Z")(d); d["proof"].(map[string]any)["extra"] = "x" }, `carries the member "extra"`},
		"a proof time of month thirteen":  {proof("2026-13-01T10:00:00Z"), "is not in the model's RFC 3339 form"},
		"a Multikey spelled in another base": {func(d map[string]any) {
			vm0(d)["publicKeyMultibase"] = "x" + didaccounts.Base58Encode(append([]byte{0xed, 0x01}, pub...))
		}, "is not an ed25519 Multikey"},
		"a Multikey of another codec": {func(d map[string]any) {
			vm0(d)["publicKeyMultibase"] = "z" + didaccounts.Base58Encode(append([]byte{0xec, 0x01}, pub...))
		}, "is not an ed25519 Multikey"},
		"a secp256k1 key with no JWK": {func(d map[string]any) {
			delete(vm0(d), "publicKeyMultibase")
			vm0(d)["type"] = "EcdsaSecp256k1VerificationKey2019"
		}, "carries no publicKeyJwk"},
		"a secp256k1 key whose y is 31 bytes": {func(d map[string]any) {
			delete(vm0(d), "publicKeyMultibase")
			vm0(d)["type"] = "EcdsaSecp256k1VerificationKey2019"
			x := cut32(secpG.x)
			vm0(d)["publicKeyJwk"] = map[string]any{"kty": "EC", "crv": "secp256k1", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(cut32(secpG.y)[1:])}
		}, "x and y must be 32-byte base64url values"},
		"a secp256k1 key whose x is 31 bytes": {func(d map[string]any) {
			delete(vm0(d), "publicKeyMultibase")
			vm0(d)["type"] = "EcdsaSecp256k1VerificationKey2019"
			vm0(d)["publicKeyJwk"] = map[string]any{"kty": "EC", "crv": "secp256k1", "x": base64.RawURLEncoding.EncodeToString(cut32(secpG.x)[1:]), "y": base64.RawURLEncoding.EncodeToString(cut32(secpG.y))}
		}, "x and y must be 32-byte base64url values"},
		"a DIDComm endpoint object of no uri": {func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = map[string]any{"accept": []any{"x"}}
		}, "needs a uri member"},
		"a DIDComm endpoint of an empty userinfo host": {func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "https://@/x"
		}, "is not an absolute http, https, ws or wss URI"},
		"a DIDComm endpoint of a port and no host": {func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "https://:443"
		}, "is not an absolute http, https, ws or wss URI"},
	} {
		err := CheckDocument(cutBase(t, c.edit))
		if !errors.Is(err, ErrDocument) || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: want a refusal saying %q, got %v", name, c.words, err)
		}
	}
	if err := CheckDocument([]byte("{")); !errors.Is(err, ErrDocument) || !strings.Contains(err.Error(), "the document has no canonical form") {
		t.Errorf("a document that is not JSON: %v", err)
	}
	for name, edit := range map[string]func(map[string]any){
		"a DIDComm endpoint over http": func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "http://a.example"
		},
		"a DIDComm endpoint over https": func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "https://a.example"
		},
		"a DIDComm endpoint over ws": func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "ws://a.example"
		},
		"a DIDComm endpoint over wss": func(d map[string]any) {
			svc0(d)["type"] = "DIDCommMessaging"
			svc0(d)["serviceEndpoint"] = "wss://a.example"
		},
		"a service of another type whose endpoint is no URI": func(d map[string]any) { svc0(d)["serviceEndpoint"] = "not a uri" },
	} {
		if err := CheckDocument(cutBase(t, edit)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}
