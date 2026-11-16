// Copyright 2024-2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package didchain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/opendlt/infrix-verify/didaccounts"
)

// THE DOCUMENT DERIVATION (infrix core part 25g, row H3: core's DIDUpdater.applyOperations and the operations of pkg/did/update.go, rule for rule). A statement chain proves who signed
// each version; that each version's document is what its statement's operations yield from the document before is proven here by applying them, in their stored order, to the JSON of
// the previous document, and comparing the canonical hash of the result with the hash the entry binds. The document model's member rules are core's:
//
//   - controller, authentication, assertionMethod, keyAgreement, capabilityInvocation and capabilityDelegation are lists written as ONE STRING when they hold one member, as an array when
//     they hold more, and omitted when empty; alsoKnownAs, verificationMethod and service are arrays, omitted when empty;
//   - a verification method or a service is inserted in its model's form: an empty optional member ("" for a string, 0 for a number, an empty list) is omitted;
//   - addVerificationMethod (verificationMethod, relationships): refused when the id exists; appends the method and its id to each named relationship (one of the five);
//     removeVerificationMethod (verificationMethodId): refused when absent; removes every method of the id and the id from every relationship;
//     updateVerificationMethod (verificationMethodId, updates): refused when absent; sets controller, keyPageUrl, keyBookUrl (strings) and threshold (an integral number 0..2^64-1) of the
//     first method of the id, an empty value omitted;
//     addService (service) / removeService (serviceId): refused when the id exists / is absent; updateService (serviceId, updates): sets type and description (strings), priority (an
//     integral number in the signed 64-bit range) and serviceEndpoint (any JSON value but null, which changes nothing) of the first service of the id, an empty value omitted;
//     addController / removeController (controllerDid): refused when it exists / is absent, and the last controller is never removed;
//     addAlsoKnownAs / removeAlsoKnownAs (identifier): refused when it exists / is absent; an identifier that is a DID of another method than infrix (or the retired lattica) is refused:
//     its binding proof is not part of a stored statement, so no statement carries one;
//     addRelationship (relationship, verificationMethodId): refused for a method that does not exist or an unknown relationship; appends the id unless the relationship holds it;
//     removeRelationship: refused for an unknown relationship; removes every occurrence (an absent id is no change);
//     deactivate and reactivate change no document (the state is the entry's);
//   - an operation of another type, a member an operation does not define, a member of the wrong kind, an update member an operation does not apply, and an empty required member are
//     refused.
//
// Every version's document is also held to the document rules (validate.go: the model, its form, Validate and the limits), as core holds it.

// ErrDerivation is a statement whose operations do not apply, or whose document is not what they yield.
var ErrDerivation = errors.New("the document is not what the statement's operations yield")

func deriveRefuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDerivation, fmt.Sprintf(format, args...))
}

var relationships = []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"}

func isRelationship(name string) bool {
	for _, r := range relationships {
		if r == name {
			return true
		}
	}
	return false
}

// decodeValue reads JSON keeping every number as its text.
func decodeValue(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// list reads a list member (one string or an array of strings; absent is empty).
func list(doc map[string]any, name string) ([]string, error) {
	switch v := doc[name].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, deriveRefuse("the member %s holds a value that is not a string", name)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, deriveRefuse("the member %s is neither a string nor an array", name)
}

// setList writes a list member: omitted when empty, one string for one member (stringForOne), an array otherwise.
func setList(doc map[string]any, name string, values []string, stringForOne bool) {
	switch {
	case len(values) == 0:
		delete(doc, name)
	case len(values) == 1 && stringForOne:
		doc[name] = values[0]
	default:
		out := make([]any, len(values))
		for i, v := range values {
			out[i] = v
		}
		doc[name] = out
	}
}

func objects(doc map[string]any, name string) ([]map[string]any, error) {
	raw, _ := doc[name].([]any)
	if doc[name] != nil && raw == nil {
		return nil, deriveRefuse("the member %s is not an array", name)
	}
	out := make([]map[string]any, len(raw))
	for i, item := range raw {
		o, ok := item.(map[string]any)
		if !ok {
			return nil, deriveRefuse("the member %s holds a value that is not an object", name)
		}
		out[i] = o
	}
	return out, nil
}

func setObjects(doc map[string]any, name string, values []map[string]any) {
	if len(values) == 0 {
		delete(doc, name)
		return
	}
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	doc[name] = out
}

func without(values []string, item string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != item {
			out = append(out, v)
		}
	}
	return out
}

func contains(values []string, item string) bool {
	for _, v := range values {
		if v == item {
			return true
		}
	}
	return false
}

// integral reads a JSON number as core's model reads it (as a double) and refuses one that is not an integer in [min, max].
func integral(v any, name string, min, max float64) (float64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, deriveRefuse("the member %s is not a number", name)
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || f != math.Trunc(f) || f < min || f > max {
		return 0, deriveRefuse("the member %s is not an integer in its range: %s", name, n)
	}
	return f, nil
}

// the ranges of the model's integers as doubles: [0, 2^64) for an unsigned member, [-2^63, 2^63) for a signed one
const (
	maxUnsigned = 18446744073709549568.0 // the largest double below 2^64
	minSigned   = -9223372036854775808.0
	maxSigned   = 9223372036854774784.0 // the largest double below 2^63
)

func unsignedText(f float64) json.Number { return json.Number(strconv.FormatUint(uint64(f), 10)) }
func signedText(f float64) json.Number   { return json.Number(strconv.FormatInt(int64(f), 10)) }

type memberKind int

const (
	kindString memberKind = iota
	kindRequiredString
	kindUnsigned
	kindSigned
	kindStrings
	kindAny
	kindJWK
)

var verificationMethodMembers = map[string]memberKind{"id": kindRequiredString, "type": kindRequiredString, "controller": kindRequiredString, "keyPageUrl": kindString, "keyBookUrl": kindString,
	"threshold": kindUnsigned, "pageIndex": kindUnsigned, "publicKeyMultibase": kindString, "publicKeyJwk": kindJWK, "blockchainAccountId": kindString}
var serviceMembers = map[string]memberKind{"id": kindRequiredString, "type": kindRequiredString, "serviceEndpoint": kindAny, "routingKeys": kindStrings, "accept": kindStrings,
	"description": kindString, "priority": kindSigned}
var jwkMembers = map[string]memberKind{"kty": kindRequiredString, "crv": kindString, "x": kindString, "y": kindString, "n": kindString, "e": kindString, "kid": kindString, "alg": kindString, "use": kindString}

// modelForm is an object in its model's form: each member of its kind, an empty optional member omitted (a required string is kept even when empty, as the model writes it).
func modelForm(raw any, members map[string]memberKind, what string) (map[string]any, error) {
	return modelFormOf(raw, members, what, true)
}

// modelFormOf is modelForm; strict reads an integer member only as an integer literal (as the model decodes JSON), and not strict as a double that is an integer (as an update value is
// read).
func modelFormOf(raw any, members map[string]memberKind, what string, strict bool) (map[string]any, error) {
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, deriveRefuse("%s is not an object", what)
	}
	out := map[string]any{}
	for name, value := range object {
		kind, known := members[name]
		if !known {
			return nil, deriveRefuse("%s carries the member %q, which it does not define", what, name)
		}
		if value == nil && kind != kindAny {
			continue
		}
		switch kind {
		case kindString, kindRequiredString:
			s, ok := value.(string)
			if !ok {
				return nil, deriveRefuse("%s.%s is not a string", what, name)
			}
			if s != "" || kind == kindRequiredString {
				out[name] = s
			}
		case kindUnsigned, kindSigned:
			min, max, text := 0.0, maxUnsigned, unsignedText
			if kind == kindSigned {
				min, max, text = minSigned, maxSigned, signedText
			}
			if n, ok := value.(json.Number); ok && strict && strings.ContainsAny(string(n), ".eE") {
				return nil, deriveRefuse("%s.%s is not an integer literal: %s", what, name, n)
			}
			f, err := integral(value, what+"."+name, min, max)
			if err != nil {
				return nil, err
			}
			if f != 0 {
				out[name] = text(f)
			}
		case kindStrings:
			items, ok := value.([]any)
			if !ok {
				return nil, deriveRefuse("%s.%s is not an array", what, name)
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return nil, deriveRefuse("%s.%s holds a value that is not a string", what, name)
				}
			}
			if len(items) > 0 {
				out[name] = items
			}
		case kindJWK:
			jwk, err := modelFormOf(value, jwkMembers, what+"."+name, strict)
			if err != nil {
				return nil, err
			}
			out[name] = jwk
		case kindAny:
			out[name] = value
		}
	}
	for name, kind := range members {
		if _, present := out[name]; !present && (kind == kindRequiredString || name == "serviceEndpoint") {
			if name == "serviceEndpoint" {
				out[name] = nil
			} else {
				out[name] = ""
			}
		}
	}
	return out, nil
}

// operationMembers are the members each operation defines (beside its type) and their kinds.
var operationMembers = map[string]map[string]string{
	"addVerificationMethod":    {"verificationMethod": "object", "relationships": "strings"},
	"removeVerificationMethod": {"verificationMethodId": "string"},
	"updateVerificationMethod": {"verificationMethodId": "string", "updates": "object"},
	"addService":               {"service": "object"},
	"removeService":            {"serviceId": "string"},
	"updateService":            {"serviceId": "string", "updates": "object"},
	"addController":            {"controllerDid": "string"},
	"removeController":         {"controllerDid": "string"},
	"addAlsoKnownAs":           {"identifier": "string", "binding": "object", "foreign": "object"},
	"removeAlsoKnownAs":        {"identifier": "string"},
	"addRelationship":          {"relationship": "string", "verificationMethodId": "string"},
	"removeRelationship":       {"relationship": "string", "verificationMethodId": "string"},
	"deactivate":               {"reactivationCommitment": "string"},
	"reactivate":               {"reactivationKey": "string", "reactivationProof": "string"},
}

// DeriveDocument applies stored operations, in order, to a document's JSON and returns the document they yield. An operation that does not apply is refused (ErrDerivation).
func DeriveDocument(document []byte, ops []Operation) (map[string]any, error) {
	value, err := decodeValue(document)
	if err != nil {
		return nil, deriveRefuse("the document is not JSON: %v", err)
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, deriveRefuse("the document is not an object")
	}
	for i, op := range ops {
		if err := applyOperation(doc, op); err != nil {
			return nil, fmt.Errorf("operation %d (%s): %w", i, op.Type, err)
		}
	}
	return doc, nil
}

func applyOperation(doc map[string]any, op Operation) error {
	defined, known := operationMembers[op.Type]
	if !known {
		return deriveRefuse("%q is not an operation of the method", op.Type)
	}
	m := map[string]any{}
	for name, raw := range op.Object {
		if name == "type" {
			continue
		}
		kind, ok := defined[name]
		if !ok {
			return deriveRefuse("the member %q is not one the operation defines", name)
		}
		v, err := decodeValue(raw)
		if err != nil {
			return deriveRefuse("the member %q is not JSON", name)
		}
		if v == nil {
			continue
		}
		switch kind {
		case "string":
			if _, ok := v.(string); !ok {
				return deriveRefuse("the member %q is not a string", name)
			}
		case "object":
			if _, ok := v.(map[string]any); !ok {
				return deriveRefuse("the member %q is not an object", name)
			}
		case "strings":
			items, ok := v.([]any)
			if !ok {
				return deriveRefuse("the member %q is not an array", name)
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return deriveRefuse("the member %q holds a value that is not a string", name)
				}
			}
		}
		m[name] = v
	}
	str := func(name string) (string, error) {
		s, _ := m[name].(string)
		if s == "" {
			return "", deriveRefuse("the member %q is required", name)
		}
		return s, nil
	}
	switch op.Type {
	case "addVerificationMethod":
		vm, err := modelForm(m["verificationMethod"], verificationMethodMembers, "verificationMethod")
		if err != nil {
			return err
		}
		id := vm["id"].(string)
		if id == "" || vm["type"] == "" || vm["controller"] == "" {
			return deriveRefuse("the verification method's id, type and controller are required")
		}
		var rels []string
		for _, r := range asStrings(m["relationships"]) {
			if !isRelationship(r) {
				return deriveRefuse("unknown relationship type: %s", r)
			}
			rels = append(rels, r)
		}
		methods, err := objects(doc, "verificationMethod")
		if err != nil {
			return err
		}
		for _, existing := range methods {
			if existing["id"] == id {
				return deriveRefuse("verification method already exists: %s", id)
			}
		}
		setObjects(doc, "verificationMethod", append(methods, vm))
		for _, r := range rels {
			values, err := list(doc, r)
			if err != nil {
				return err
			}
			setList(doc, r, append(values, id), true)
		}
	case "removeVerificationMethod":
		id, err := str("verificationMethodId")
		if err != nil {
			return err
		}
		methods, err := objects(doc, "verificationMethod")
		if err != nil {
			return err
		}
		kept := make([]map[string]any, 0, len(methods))
		for _, vm := range methods {
			if vm["id"] != id {
				kept = append(kept, vm)
			}
		}
		if len(kept) == len(methods) {
			return deriveRefuse("verification method not found: %s", id)
		}
		setObjects(doc, "verificationMethod", kept)
		for _, r := range relationships {
			values, err := list(doc, r)
			if err != nil {
				return err
			}
			setList(doc, r, without(values, id), true)
		}
	case "updateVerificationMethod", "updateService":
		target, members, listName := "verificationMethodId", verificationMethodMembers, "verificationMethod"
		allowed := map[string]bool{"controller": true, "keyPageUrl": true, "keyBookUrl": true, "threshold": true}
		if op.Type == "updateService" {
			target, members, listName = "serviceId", serviceMembers, "service"
			allowed = map[string]bool{"type": true, "description": true, "priority": true, "serviceEndpoint": true}
		}
		id, err := str(target)
		if err != nil {
			return err
		}
		updates, _ := m["updates"].(map[string]any)
		if len(updates) == 0 {
			return deriveRefuse("no updates specified")
		}
		for name, value := range updates {
			if !allowed[name] {
				return deriveRefuse("the update member %q is not one this operation applies", name)
			}
			if value == nil && name != "serviceEndpoint" {
				return deriveRefuse("the update member %q is null", name)
			}
		}
		items, err := objects(doc, listName)
		if err != nil {
			return err
		}
		index := -1
		for i, item := range items {
			if item["id"] == id {
				index = i
				break
			}
		}
		for name, value := range updates {
			if name == "serviceEndpoint" && value == nil {
				continue // a null endpoint changes nothing
			}
			single, err := modelFormOf(map[string]any{name: value}, members, "updates", false)
			if err != nil {
				return err
			}
			if index < 0 {
				continue
			}
			if v, present := single[name]; present && (name != "type" || v != "") {
				items[index][name] = v
			} else if name == "type" {
				items[index][name] = ""
			} else {
				delete(items[index], name)
			}
		}
		if index < 0 {
			return deriveRefuse("%s not found: %s", map[string]string{"verificationMethod": "verification method", "service": "service"}[listName], id)
		}
		// the items are the document's own objects (objects returns them, not copies), so each update above is in the document already (part 25i: a setObjects here
		// rewrote the same objects and no cut could tell it was there)
	case "addService":
		svc, err := modelForm(m["service"], serviceMembers, "service")
		if err != nil {
			return err
		}
		if svc["id"] == "" || svc["type"] == "" || svc["serviceEndpoint"] == nil {
			return deriveRefuse("the service's id, type and endpoint are required")
		}
		services, err := objects(doc, "service")
		if err != nil {
			return err
		}
		for _, existing := range services {
			if existing["id"] == svc["id"] {
				return deriveRefuse("service already exists: %s", svc["id"])
			}
		}
		setObjects(doc, "service", append(services, svc))
	case "removeService":
		id, err := str("serviceId")
		if err != nil {
			return err
		}
		services, err := objects(doc, "service")
		if err != nil {
			return err
		}
		kept := make([]map[string]any, 0, len(services))
		for _, svc := range services {
			if svc["id"] != id {
				kept = append(kept, svc)
			}
		}
		if len(kept) == len(services) {
			return deriveRefuse("service not found: %s", id)
		}
		setObjects(doc, "service", kept)
	case "addController", "removeController":
		did, err := str("controllerDid")
		if err != nil {
			return err
		}
		controllers, err := list(doc, "controller")
		if err != nil {
			return err
		}
		if op.Type == "addController" {
			if contains(controllers, did) {
				return deriveRefuse("controller already exists: %s", did)
			}
			setList(doc, "controller", append(controllers, did), true)
			return nil
		}
		if !contains(controllers, did) {
			return deriveRefuse("controller not found: %s", did)
		}
		if len(without(controllers, did)) == 0 {
			return deriveRefuse("cannot remove last controller")
		}
		setList(doc, "controller", without(controllers, did), true)
	case "addAlsoKnownAs", "removeAlsoKnownAs":
		// the model's foreign document has no member a statement can carry, and a binding has its own eight members
		if foreign, ok := m["foreign"].(map[string]any); ok && len(foreign) != 0 {
			return deriveRefuse("the member \"foreign\" carries members the model does not define")
		}
		if binding, ok := m["binding"].(map[string]any); ok {
			for name := range binding {
				switch name {
				case "infrixDid", "foreignDid", "nonce", "infrixKeyId", "infrixProofValue", "foreignKeyId", "foreignProofValue", "foreignSigner":
				default:
					return deriveRefuse("the binding carries the member %q, which it does not define", name)
				}
			}
		}
		identifier, err := str("identifier")
		if err != nil {
			return err
		}
		aliases, err := list(doc, "alsoKnownAs")
		if err != nil {
			return err
		}
		if op.Type == "addAlsoKnownAs" {
			if contains(aliases, identifier) {
				return deriveRefuse("alsoKnownAs already exists: %s", identifier)
			}
			if rest, isDID := strings.CutPrefix(identifier, "did:"); isDID {
				if method, _, _ := strings.Cut(rest, ":"); method != "infrix" && method != "lattica" {
					binding, _ := m["binding"].(map[string]any)
					if err := verifyStoredBinding(binding, identifier, doc); err != nil {
						return err
					}
				}
			}
			setList(doc, "alsoKnownAs", append(aliases, identifier), false)
			return nil
		}
		if !contains(aliases, identifier) {
			return deriveRefuse("alsoKnownAs not found: %s", identifier)
		}
		setList(doc, "alsoKnownAs", without(aliases, identifier), false)
	case "addRelationship", "removeRelationship":
		rel, err := str("relationship")
		if err != nil {
			return err
		}
		id, err := str("verificationMethodId")
		if err != nil {
			return err
		}
		if op.Type == "addRelationship" {
			methods, err := objects(doc, "verificationMethod")
			if err != nil {
				return err
			}
			found := false
			for _, vm := range methods {
				found = found || vm["id"] == id
			}
			if !found {
				return deriveRefuse("verification method not found: %s", id)
			}
		}
		if !isRelationship(rel) {
			return deriveRefuse("unknown relationship type: %s", rel)
		}
		values, err := list(doc, rel)
		if err != nil {
			return err
		}
		if op.Type == "addRelationship" {
			if !contains(values, id) {
				setList(doc, rel, append(values, id), true)
			}
			return nil
		}
		setList(doc, rel, without(values, id), true)
	}
	return nil
}

func asStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.(string))
	}
	return out
}

// DerivedDocumentHash is the canonical hash of a derived document.
func DerivedDocumentHash(doc map[string]any) ([]byte, error) {
	text, err := json.Marshal(doc)
	if err != nil {
		return nil, deriveRefuse("the derived document does not encode: %v", err)
	}
	return DocumentHash(text)
}

// verifyDerivation holds every later entry's document to the one its operations yield from the document before it.
func verifyDerivation(history []*Entry) error {
	for i := 1; i < len(history); i++ {
		derived, err := DeriveDocument(history[i-1].Document, history[i].Operations)
		if err != nil {
			return fmt.Errorf("%w: entry %d: the statement's operations do not apply to version %s: %v", ErrStatementChain, i, history[i-1].VersionID, err)
		}
		hash, err := DerivedDocumentHash(derived)
		if err != nil || !bytes.Equal(hash, history[i].DocumentHash) {
			return fmt.Errorf("%w: entry %d: %w from version %s", ErrStatementChain, i, ErrDerivation, history[i-1].VersionID)
		}
	}
	return nil
}

// verifyStoredBinding verifies a cross-method alias binding from the stored statement alone (core's VerifyStoredAliasBinding, rule for rule): the binding names the alias and the
// document's own DID, and its nonce is at least 16 characters. The foreign side:
//   - a did:key: its identifier is an Ed25519 Multikey, the foreign key id is <did>#<identifier>, foreignProofValue is that key's Ed25519 signature of the binding statement
//     ("infrix-alias-binding/v1", infrixDid, foreignDid and nonce on four lines), and the binding carries no foreignSigner;
//   - a did:pkh (part 25h): its CAIP-10 account is valid under its namespace's address standard, the foreign key id is <did>#blockchainAccountId, and foreignProofValue is the
//     account's signature of the binding statement in its namespace's message-signing standard, verified by the chain profile's namespace verifier with foreignSigner as the signer.
//
// Any other method (a did:web, whose keys its host serves) is refused by name. An infrixProofValue, when present, verifies under the document's authentication key infrixKeyId.
func verifyStoredBinding(binding map[string]any, identifier string, doc map[string]any) error {
	if binding == nil {
		return deriveRefuse("%q is a DID of another method and needs a verified binding", identifier)
	}
	str := func(name string) string { s, _ := binding[name].(string); return s }
	foreign, infrix, nonce := str("foreignDid"), str("infrixDid"), str("nonce")
	if foreign != identifier {
		return deriveRefuse("the binding names %q, not the alias %q", foreign, identifier)
	}
	if id, _ := doc["id"].(string); infrix != id {
		return deriveRefuse("the binding names the Infrix DID %q, not the document's", infrix)
	}
	if len(nonce) < 16 {
		return deriveRefuse("the binding's nonce is shorter than 16 characters")
	}
	statement := []byte("infrix-alias-binding/v1\n" + infrix + "\n" + foreign + "\n" + nonce)
	signature, serr := base64.StdEncoding.DecodeString(str("foreignProofValue"))
	signer, gerr := base64.StdEncoding.DecodeString(str("foreignSigner"))
	if serr != nil || gerr != nil {
		return deriveRefuse("the binding's foreignProofValue or foreignSigner is not base64")
	}
	switch {
	case strings.HasPrefix(foreign, "did:key:"):
		multikey := strings.TrimPrefix(foreign, "did:key:")
		raw := []byte(nil)
		if strings.HasPrefix(multikey, "z") {
			raw = didaccounts.Base58Decode(multikey[1:])
		}
		if len(raw) != 34 || raw[0] != 0xed || raw[1] != 0x01 {
			return deriveRefuse("the did:key %q is not an Ed25519 Multikey", foreign)
		}
		if str("foreignKeyId") != foreign+"#"+multikey {
			return deriveRefuse("the foreign key is not the did:key's own key")
		}
		if len(signer) != 0 {
			return deriveRefuse("a did:key binding carries no foreignSigner: the did:key is its own key")
		}
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(raw[2:], statement, signature) {
			return deriveRefuse("the foreign controller's signature does not verify")
		}
	case strings.HasPrefix(foreign, "did:pkh:"):
		parts := strings.Split(strings.TrimPrefix(foreign, "did:pkh:"), ":")
		if len(parts) != 3 {
			return deriveRefuse("the did:pkh %q is not namespace:reference:account (CAIP-10)", foreign)
		}
		canonical, err := didaccounts.NormalizeChainAccount(parts[0], parts[1], parts[2])
		if err != nil {
			return deriveRefuse("the did:pkh %q does not name an account of a supported namespace: %v", foreign, err)
		}
		verifier, ok := chainVerifiers[parts[0]]
		if !ok {
			return deriveRefuse("the did:pkh namespace %q has no verifier", parts[0])
		}
		if str("foreignKeyId") != foreign+"#blockchainAccountId" {
			return deriveRefuse("the foreign key is not the did:pkh's own method #blockchainAccountId")
		}
		if err := verifier.Verify(ChainAccount{Namespace: parts[0], Reference: parts[1], Account: canonical}, statement, signer, signature); err != nil {
			return deriveRefuse("the foreign account's signature does not verify under %s: %v", verifier.Scheme(), err)
		}
	default:
		return deriveRefuse("%q: a stored binding verifies only a did:key (its identifier is its key) or a did:pkh (its account signs in its chain's standard)", foreign)
	}
	if text := str("infrixProofValue"); text != "" {
		infrixSignature, err := base64.StdEncoding.DecodeString(text)
		keys, kerr := authenticationKeysOf(doc, str("infrixKeyId"))
		if err != nil || kerr != nil || !ed25519.Verify(keys, statement, infrixSignature) {
			return deriveRefuse("the Infrix controller's signature does not verify")
		}
	}
	return nil
}

// authenticationKeysOf is the Ed25519 Multikey of the authentication method keyID of a document.
func authenticationKeysOf(doc map[string]any, keyID string) (ed25519.PublicKey, error) {
	refs, err := list(doc, "authentication")
	if err != nil || !contains(refs, keyID) {
		return nil, deriveRefuse("the Infrix key %q is not an authentication method of the document", keyID)
	}
	methods, _ := objects(doc, "verificationMethod")
	for _, vm := range methods {
		if vm["id"] == keyID {
			mb, _ := vm["publicKeyMultibase"].(string)
			if strings.HasPrefix(mb, "z") {
				if raw := didaccounts.Base58Decode(mb[1:]); len(raw) == 34 && raw[0] == 0xed && raw[1] == 0x01 {
					return ed25519.PublicKey(raw[2:]), nil
				}
			}
		}
	}
	return nil, deriveRefuse("the Infrix key %q has no Ed25519 Multikey in the document", keyID)
}
