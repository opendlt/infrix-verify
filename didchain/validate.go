// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// THE DOCUMENT RULES every version of an anon or chain history meets (infrix core part 25g: core's CheckRegistryDocument, ContractDIDDocument.Validate and the updater's limits, rule
// for rule; the shared vectors' documentValidity section pins each):
//
//   - THE MODEL: the members @context (strings), id, controller, alsoKnownAs, verificationMethod, the five relationships, service and proof, each of its kind, no other member; a
//     verification method, a service, a JWK and a proof of their models' members and kinds; an integer member is an integer literal;
//   - THE MODEL'S FORM: the document is stored exactly as its model encodes it (a list of one member as a string, an empty member omitted, a required string written even when empty,
//     a proof time as RFC 3339 with no trailing fraction zeros and Z for a zero offset): its canonical form equals the canonical form of its model's encoding;
//   - VALIDATE: the W3C DID context is named; every verification method has an id, a type and a controller; an AccumulateKeyPage method has a keyPageUrl; a Multikey or an
//     Ed25519VerificationKey2020 carries no publicKeyJwk and a publicKeyMultibase that is "z" + base58btc(0xed01 || 32 bytes); an EcdsaSecp256k1VerificationKey2019 carries no
//     publicKeyMultibase and a publicKeyJwk {kty EC, crv secp256k1, x, y} of 32-byte base64url coordinates that are a point of the curve; every service has an id, a type and an endpoint
//     that is not null; a DIDCommMessaging service's endpoint is a URI (or an object with a uri) with a host on http, https, ws or wss, and each routing key (of the service and of the
//     endpoint object) begins with "did:";
//   - THE LIMITS: at most 100 verification methods, 50 services and 10 controllers.

// ErrDocument is a document a history may not hold.
var ErrDocument = errors.New("the document breaks a rule every version meets")

func docRefuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDocument, fmt.Sprintf(format, args...))
}

var proofMembers = map[string]memberKind{"type": kindRequiredString, "created": kindRequiredString, "verificationMethod": kindRequiredString, "proofPurpose": kindRequiredString,
	"proofValue": kindString, "jws": kindString, "challenge": kindString}

// modelTime is the RFC 3339 form Go's encoder writes: no trailing zeros of a fraction, Z for a zero offset.
var modelTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d*[1-9])?(Z|[+-]\d{2}:\d{2})$`)

// modelDocument is the document's model encoding, refusing a member the model does not define or of another kind.
func modelDocument(raw []byte) (map[string]any, error) {
	value, err := decodeValue(raw)
	if err != nil {
		return nil, docRefuse("the document is not JSON")
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, docRefuse("the document is not an object")
	}
	out := map[string]any{}
	for name, v := range doc {
		switch name {
		case "@context":
			if v == nil {
				out[name] = nil
				continue
			}
			items, ok := v.([]any)
			if !ok {
				return nil, docRefuse("@context is not an array")
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return nil, docRefuse("@context holds a value that is not a string")
				}
			}
			out[name] = items
		case "id":
			if _, ok := v.(string); !ok && v != nil {
				return nil, docRefuse("id is not a string")
			}
			if v != nil {
				out[name] = v
			}
		case "controller", "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation":
			values, err := list(map[string]any{name: v}, name)
			if err != nil {
				return nil, docRefuse("%v", err)
			}
			setList(out, name, values, true)
		case "alsoKnownAs":
			if v == nil {
				continue
			}
			items, ok := v.([]any)
			if !ok {
				return nil, docRefuse("alsoKnownAs is not an array")
			}
			values, err := list(map[string]any{name: items}, name)
			if err != nil {
				return nil, docRefuse("%v", err)
			}
			setList(out, name, values, false)
		case "verificationMethod", "service":
			if v == nil {
				continue
			}
			items, ok := v.([]any)
			if !ok {
				return nil, docRefuse("%s is not an array", name)
			}
			members := verificationMethodMembers
			if name == "service" {
				members = serviceMembers
			}
			var forms []map[string]any
			for i, item := range items {
				form, err := modelForm(item, members, fmt.Sprintf("%s %d", name, i))
				if err != nil {
					return nil, docRefuse("%v", err)
				}
				forms = append(forms, form)
			}
			setObjects(out, name, forms)
		case "proof":
			if v == nil {
				continue
			}
			form, err := modelForm(v, proofMembers, "proof")
			if err != nil {
				return nil, docRefuse("%v", err)
			}
			created, _ := form["created"].(string)
			if _, err := time.Parse(time.RFC3339Nano, created); err != nil || !modelTime.MatchString(created) || strings.HasSuffix(created, "+00:00") || strings.HasSuffix(created, "-00:00") {
				return nil, docRefuse("the proof's time %q is not in the model's RFC 3339 form", created)
			}
			out[name] = form
		default:
			return nil, docRefuse("the document carries the member %q, which the model does not define", name)
		}
	}
	if _, ok := out["@context"]; !ok {
		out["@context"] = nil
	}
	if _, ok := out["id"]; !ok {
		out["id"] = ""
	}
	return out, nil
}

// CheckDocument holds a document's JSON to the rules every version of an anon or chain history meets.
func CheckDocument(raw []byte) error {
	stored, err := CanonicalizeJSON(raw)
	if err != nil {
		return docRefuse("the document has no canonical form: %v", err)
	}
	doc, err := modelDocument(raw)
	if err != nil {
		return err
	}
	text, _ := json.Marshal(doc)
	model, err := CanonicalizeJSON(text)
	if err != nil || !bytes.Equal(model, stored) {
		return docRefuse("the document is not in its model's form")
	}
	if id, _ := doc["id"].(string); id == "" {
		return docRefuse("missing DID ID")
	}
	contexts, _ := doc["@context"].([]any)
	named := false
	for _, c := range contexts {
		named = named || c == "https://www.w3.org/ns/did/v1"
	}
	if !named {
		return docRefuse("missing W3C DID context")
	}
	methods, _ := objects(doc, "verificationMethod")
	for i, vm := range methods {
		if err := checkVerificationMethod(i, vm); err != nil {
			return err
		}
	}
	services, _ := objects(doc, "service")
	for i, svc := range services {
		if err := checkService(i, svc); err != nil {
			return err
		}
	}
	controllers, _ := list(doc, "controller")
	switch {
	case len(methods) > 100:
		return docRefuse("verification method limit exceeded: %d > 100", len(methods))
	case len(services) > 50:
		return docRefuse("service limit exceeded: %d > 50", len(services))
	case len(controllers) > 10:
		return docRefuse("controller limit exceeded: %d > 10", len(controllers))
	}
	return nil
}

func checkVerificationMethod(i int, vm map[string]any) error {
	id, _ := vm["id"].(string)
	kind, _ := vm["type"].(string)
	controller, _ := vm["controller"].(string)
	switch {
	case id == "":
		return docRefuse("verification method %d missing ID", i)
	case kind == "":
		return docRefuse("verification method %d missing type", i)
	case controller == "":
		return docRefuse("verification method %d missing controller", i)
	}
	multibase, _ := vm["publicKeyMultibase"].(string)
	jwk, hasJWK := vm["publicKeyJwk"].(map[string]any)
	switch kind {
	case "AccumulateKeyPage":
		if page, _ := vm["keyPageUrl"].(string); page == "" {
			return docRefuse("verification method %d missing keyPageUrl", i)
		}
	case "Multikey", "Ed25519VerificationKey2020":
		if hasJWK {
			return docRefuse("%s %s carries publicKeyJwk; its registered form is publicKeyMultibase", kind, id)
		}
		raw := []byte(nil)
		if strings.HasPrefix(multibase, "z") {
			raw = didaccounts.Base58Decode(multibase[1:])
		}
		if len(raw) != 34 || raw[0] != 0xed || raw[1] != 0x01 {
			return docRefuse("%s %s: %q is not an ed25519 Multikey", kind, id, multibase)
		}
	case "EcdsaSecp256k1VerificationKey2019":
		if multibase != "" {
			return docRefuse("%s %s carries publicKeyMultibase; its registered form is publicKeyJwk", kind, id)
		}
		if !hasJWK {
			return docRefuse("%s %s carries no publicKeyJwk", kind, id)
		}
		if jwk["kty"] != "EC" || jwk["crv"] != "secp256k1" {
			return docRefuse("%s %s: publicKeyJwk is not kty EC crv secp256k1", kind, id)
		}
		xText, _ := jwk["x"].(string)
		yText, _ := jwk["y"].(string)
		// a coordinate that does not decode reads as empty, which the lengths refuse (part 25i: the decoders' errors decided nothing the lengths did not)
		// restored from part 25i; EQUIVALENT in the cut tables: a decoder error leaves no 32-byte value, which the length test refuses too, so the predicates agree on every input
		x, errX := base64.RawURLEncoding.DecodeString(xText)
		y, errY := base64.RawURLEncoding.DecodeString(yText)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return docRefuse("%s %s: publicKeyJwk x and y must be 32-byte base64url values", kind, id)
		}
		if _, err := ParseSecp256k1PublicKey(append([]byte{4}, append(x, y...)...)); err != nil {
			return docRefuse("%s %s: publicKeyJwk is not a point on secp256k1", kind, id)
		}
	}
	return nil
}

var didcommSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true}

func checkService(i int, svc map[string]any) error {
	id, _ := svc["id"].(string)
	kind, _ := svc["type"].(string)
	switch {
	case id == "":
		return docRefuse("service %d missing ID", i)
	case kind == "":
		return docRefuse("service %d missing type", i)
	case svc["serviceEndpoint"] == nil:
		return docRefuse("service %d missing serviceEndpoint", i)
	}
	if kind != "DIDCommMessaging" {
		return nil
	}
	var uri string
	var routing []any
	if keys, ok := svc["routingKeys"].([]any); ok {
		routing = append(routing, keys...)
	}
	switch e := svc["serviceEndpoint"].(type) {
	case string:
		uri = e
	case map[string]any:
		uri, _ = e["uri"].(string)
		if uri == "" {
			return docRefuse("service %s: a DIDCommMessaging endpoint object needs a uri member", id)
		}
		if keys, ok := e["routingKeys"].([]any); ok {
			routing = append(routing, keys...)
		}
	default:
		return docRefuse("service %s: a DIDCommMessaging endpoint is a URI or an object with a uri member", id)
	}
	if !didcommURI(uri) {
		return docRefuse("service %s: endpoint %q is not an absolute http, https, ws or wss URI", id, uri)
	}
	for _, k := range routing {
		if s, _ := k.(string); !strings.HasPrefix(s, "did:") {
			return docRefuse("service %s: routing key %v is not a DID URL", id, k)
		}
	}
	return nil
}

// didcommURI is an absolute URI on a DIDComm transport with a host: scheme "://" authority, the authority (after any userinfo) not empty, no space or control character.
func didcommURI(uri string) bool {
	scheme, rest, ok := strings.Cut(uri, "://")
	if !ok || !didcommSchemes[strings.ToLower(scheme)] || strings.ContainsFunc(uri, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		authority = authority[i+1:]
	}
	host := authority
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return host != ""
}

// verifyDocuments holds every entry's document to the document rules.
func verifyDocuments(history []*Entry) error {
	for i, e := range history {
		if err := CheckDocument(e.Document); err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrStatementChain, i, err)
		}
	}
	return nil
}
