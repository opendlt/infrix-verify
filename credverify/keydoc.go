// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// THE ISSUER DOCUMENT, READ WITHOUT TRUSTING THE NODE.
//
// An Ed25519VerificationKey2020 (and a Multikey) publishes its key as publicKeyMultibase: "z" +
// base58btc(0xed01 || the 32 key bytes). The node wrote "m" + base64 of the bare key before Wave
// D1d. This is an independent implementation of the reader (it uses this package's own base58,
// not infrix-schema's or infrix-core's) and the vector in keydoc_test.go is the one all three pin.

// ErrIssuerDocument marks an issuer document this verifier will not take a key from.
var ErrIssuerDocument = errors.New("credverify: unusable issuer document")

// Ed25519Suite2020Context defines Ed25519VerificationKey2020 and Ed25519Signature2020.
const Ed25519Suite2020Context = "https://w3id.org/security/suites/ed25519-2020/v1"

// ParseEd25519Multikey decodes publicKeyMultibase. It refuses every other multibase base,
// multicodec and length, including the earlier "m"+base64 spelling.
func ParseEd25519Multikey(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, "z") {
		return nil, fmt.Errorf("%w: %q is not multibase base58btc (no z prefix)", ErrIssuerDocument, s)
	}
	raw, ok := base58btcDecode(s[1:])
	if !ok || len(raw) != 2+ed25519.PublicKeySize || raw[0] != 0xed || raw[1] != 0x01 {
		return nil, fmt.Errorf("%w: %q is not 0xed01 followed by a 32-byte Ed25519 key", ErrIssuerDocument, s)
	}
	return ed25519.PublicKey(raw[2:]), nil
}

type issuerDocument struct {
	Context            json.RawMessage `json:"@context"`
	ID                 string          `json:"id"`
	VerificationMethod []struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	} `json:"verificationMethod"`
	AssertionMethod []json.RawMessage `json:"assertionMethod"`
}

// ResolverFromIssuerDocument returns a KeyResolver backed by one issuer DID document the CALLER
// vouches for (fetched and trusted by the caller, never read out of the credential). The document
// must name the DID asked for, list the verification method under assertionMethod, give it the
// type Ed25519VerificationKey2020 or Multikey with a z6Mk key, and, for Ed25519VerificationKey2020,
// name the context that defines the type.
func ResolverFromIssuerDocument(doc []byte) KeyResolver {
	return func(did, verificationMethod string) (ed25519.PublicKey, error) {
		var d issuerDocument
		if err := json.Unmarshal(doc, &d); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIssuerDocument, err)
		}
		if d.ID != did {
			return nil, fmt.Errorf("%w: the document is for %q, not %q", ErrIssuerDocument, d.ID, did)
		}
		want := verificationMethod
		if strings.HasPrefix(want, "#") {
			want = d.ID + want
		}
		listed := false
		for _, raw := range d.AssertionMethod {
			var ref string
			if json.Unmarshal(raw, &ref) == nil && (ref == want || (strings.HasPrefix(ref, "#") && d.ID+ref == want)) {
				listed = true
			}
		}
		for _, vm := range d.VerificationMethod {
			id := vm.ID
			if strings.HasPrefix(id, "#") {
				id = d.ID + id
			}
			if id != want {
				continue
			}
			if !listed {
				return nil, fmt.Errorf("%w: %s is not listed under assertionMethod", ErrIssuerDocument, want)
			}
			switch vm.Type {
			case "Ed25519VerificationKey2020":
				if !strings.Contains(string(d.Context), `"`+Ed25519Suite2020Context+`"`) {
					return nil, fmt.Errorf("%w: the document names no context that defines Ed25519VerificationKey2020", ErrIssuerDocument)
				}
			case "Multikey":
			default:
				return nil, fmt.Errorf("%w: verification method type %q is not an Ed25519 Multikey type", ErrIssuerDocument, vm.Type)
			}
			if vm.Controller != d.ID {
				return nil, fmt.Errorf("%w: %s is controlled by %q, not by the issuer %q", ErrIssuerDocument, want, vm.Controller, d.ID)
			}
			return ParseEd25519Multikey(vm.PublicKeyMultibase)
		}
		return nil, fmt.Errorf("%w: no verification method %s", ErrIssuerDocument, want)
	}
}
