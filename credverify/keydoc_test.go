// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// The shared vector: the W3C CCG Ed25519Signature2020 test key as publicKeyBase58 and as publicKeyMultibase.
// The same values are pinned in infrix-core (pkg/did) and infrix-schema (credential).
const (
	multikeyVectorBase58    = "dbDmZLTWuEYYZNHFLKLoRkEX4sZykkSLNQLXvMUyMB1"
	multikeyVectorMultibase = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	multikeyVectorKeyHex    = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44"
)

func TestMultikeyVector(t *testing.T) {
	raw, ok := base58btcDecode(multikeyVectorBase58)
	if !ok || hex.EncodeToString(raw) != multikeyVectorKeyHex {
		t.Fatalf("the W3C publicKeyBase58 decodes to %x", raw)
	}
	got, err := ParseEd25519Multikey(multikeyVectorMultibase)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("ParseEd25519Multikey(%s) = %x, %v", multikeyVectorMultibase, got, err)
	}
	if enc := "z" + base58btcEncode(append([]byte{0xed, 0x01}, raw...)); enc != multikeyVectorMultibase {
		t.Fatalf("encoding the vector gives %s", enc)
	}
}

func issuerDoc(typ, ctx, mb, listed string) []byte {
	return []byte(fmt.Sprintf(`{"@context":[%s],"id":"did:web:issuer.example.com","verificationMethod":[{"id":"did:web:issuer.example.com#key-1","type":%q,"controller":"did:web:issuer.example.com","publicKeyMultibase":%q}],"assertionMethod":[%s]}`,
		ctx, typ, mb, listed))
}

func TestResolverFromIssuerDocument(t *testing.T) {
	const did, vm = "did:web:issuer.example.com", "did:web:issuer.example.com#key-1"
	std := `"https://www.w3.org/ns/did/v1","` + Ed25519Suite2020Context + `"`
	listed := `"` + vm + `"`
	pub, err := ResolverFromIssuerDocument(issuerDoc("Ed25519VerificationKey2020", std, multikeyVectorMultibase, listed))(did, vm)
	if err != nil || hex.EncodeToString(pub) != multikeyVectorKeyHex {
		t.Fatalf("the standard issuer document did not resolve: %x, %v", pub, err)
	}
	if _, err := ResolverFromIssuerDocument(issuerDoc("Multikey", `"https://www.w3.org/ns/did/v1"`, multikeyVectorMultibase, listed))(did, "#key-1"); err != nil {
		t.Errorf("a Multikey document with a fragment reference did not resolve: %v", err)
	}
	legacy := "m" + "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	for name, doc := range map[string][]byte{
		"base64 key":                 issuerDoc("Ed25519VerificationKey2020", std, legacy, listed),
		"no defining context":        issuerDoc("Ed25519VerificationKey2020", `"https://www.w3.org/ns/did/v1"`, multikeyVectorMultibase, listed),
		"not under assertionMethod":  issuerDoc("Ed25519VerificationKey2020", std, multikeyVectorMultibase, ``),
		"wrong type":                 issuerDoc("Ed25519VerificationKey2018", std, multikeyVectorMultibase, listed),
		"wrong multicodec":           issuerDoc("Ed25519VerificationKey2020", std, "z"+base58btcEncode(append([]byte{0xe7, 0x01}, make([]byte, 32)...)), listed),
		"document of another issuer": []byte(`{"@context":[],"id":"did:web:other.example.com"}`),
		"not JSON":                   []byte(`nope`),
	} {
		if _, err := ResolverFromIssuerDocument(doc)(did, vm); !errors.Is(err, ErrIssuerDocument) {
			t.Errorf("PLANTED DEFECT NOT REFUSED (%s): %v", name, err)
		}
	}
}
