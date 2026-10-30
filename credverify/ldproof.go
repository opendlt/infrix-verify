// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package credverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/opendlt/infrix-schema/credential"
)

// THE CONFORMING Ed25519Signature2020 CHECK, WRITTEN INDEPENDENTLY OF infrix-core
//
// A credential whose proof is Ed25519Signature2020 and whose @context names the suite context carries
// the conforming proof: Ed25519 over SHA-256(RDFC-1.0 of the proof configuration) ||
// SHA-256(RDFC-1.0 of the document without proof). This file checks it with its own JSON-LD loader,
// canonicalizer and refusals (the same rules infrix-core's dataintegrity package applies, written again
// here because an offline verifier must not borrow its judgement from the node's code). A credential
// without the suite context cannot be read by a JSON-LD processor as that suite, so it can only carry
// the legacy construction (Ed25519 over sha256 of the JSON), which is verified under the typed label
// LegacyConstruction and reported in Report.Legacy.

// LegacyHolderConstruction is the label of the holder-proof construction issued under the Ed25519Signature2020 name before
// presentations were signed through the suite: Ed25519 over SHA-256(canonical proof configuration) || SHA-256(presentation
// JSON without proof), the one infrix-schema's VerifiablePresentation.SigningContent computes.
const LegacyHolderConstruction = "legacy:holder-proof-configuration-digest"

// LegacyConstruction is the label of the signature construction issued under the Ed25519Signature2020 name
// before the suite was implemented: Ed25519 over sha256(json.Marshal(credential without proof)).
const LegacyConstruction = "legacy:sha256-json-ed25519"

// MaxSymmetricNeighbours bounds the poison-graph search RDFC-1.0 would otherwise run on adversarial blank nodes.
const MaxSymmetricNeighbours = 6

//go:embed contexts/*.jsonld
var contextFiles embed.FS

// The contexts the node's credentials name, pinned by SHA-256 so a context is never fetched and never differs.
var pinnedContexts = map[string]struct{ file, sha256 string }{
	"https://www.w3.org/2018/credentials/v1":           {"contexts/credentials-v1.jsonld", "ab4ddd9a531758807a79a5b450510d61ae8d147eab966cc9a200c07095b0cdcc"},
	"https://w3id.org/vc/status-list/2021/v1":          {"contexts/status-list-2021-v1.jsonld", "6dd06a52bedb771e059c1083ba8ba7848dce22f6b4a8cfa0b98ba3fc188870e4"},
	"https://w3id.org/security/suites/ed25519-2020/v1": {"contexts/ed25519-2020-v1.jsonld", "b9e1ab971fd8bf2c7553e0c4a9438e0b9450afde1ea1ca5b2492368b9f549588"},
	"https://infrix.opendlt.org/ns/credentials/v1":     {"contexts/infrix-claims-v1.jsonld", "cdbdf3db0966e8a4c2c2d129a8596409bd2bd83c4467f818d1c2929e1e0b3a55"},
}

// PinnedContext is an operator context pinned by SHA-256 (Options.PinnedContexts).
type PinnedContext struct {
	URL      string
	SHA256   string
	Document []byte
}

// ErrLinkedData marks a failure of the conforming-suite check, with the reason in the message.
var ErrLinkedData = errors.New("credverify: Ed25519Signature2020 check failed")

type pinnedLoader struct{ docs map[string][]byte }

func newPinnedLoader(extra []PinnedContext) (*pinnedLoader, error) {
	l := &pinnedLoader{docs: map[string][]byte{}}
	pin := func(url, want string, raw []byte) error {
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			return fmt.Errorf("%w: context %s has sha256 %s, pinned %s", ErrLinkedData, url, got, want)
		}
		l.docs[url] = raw
		return nil
	}
	for url, p := range pinnedContexts {
		raw, err := contextFiles.ReadFile(p.file)
		if err != nil {
			return nil, err
		}
		if err := pin(url, p.sha256, raw); err != nil {
			return nil, err
		}
	}
	for _, e := range extra {
		if _, taken := l.docs[e.URL]; taken {
			return nil, fmt.Errorf("%w: context %s is already pinned", ErrLinkedData, e.URL)
		}
		if err := pin(e.URL, e.SHA256, e.Document); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func (l *pinnedLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	raw, ok := l.docs[u]
	if !ok {
		return nil, fmt.Errorf("%w: context %s is not pinned (remote fetch refused)", ErrLinkedData, u)
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: doc}, nil
}

func ldOptions(l ld.DocumentLoader) *ld.JsonLdOptions {
	o := ld.NewJsonLdOptions("")
	o.ProcessingMode = ld.JsonLd_1_1
	o.DocumentLoader = l
	o.SafeMode = true // content the contexts do not define is refused, never dropped
	o.Algorithm = ld.AlgorithmURDNA2015
	o.Format = "application/n-quads"
	return o
}

// canonicalize returns the RDFC-1.0 canonical N-Quads of a JSON-LD document.
func canonicalize(doc map[string]interface{}, l *pinnedLoader) (string, error) {
	opts := ldOptions(l)
	proc := ld.NewJsonLdProcessor()
	expanded, err := proc.Expand(doc, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLinkedData, err)
	}
	if err := requireAbsolute(expanded); err != nil {
		return "", err
	}
	toRDF := ldOptions(l)
	toRDF.Format = ""
	ds, err := proc.ToRDF(doc, toRDF)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLinkedData, err)
	}
	dataset, ok := ds.(*ld.RDFDataset)
	if !ok {
		return "", fmt.Errorf("%w: to-RDF returned %T", ErrLinkedData, ds)
	}
	if err := refusePoison(dataset); err != nil {
		return "", err
	}
	out, err := ld.NewJsonLdApi().Normalize(dataset, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLinkedData, err)
	}
	s, _ := out.(string)
	return escapeControls(s), nil
}

// escapeControls writes the control characters json-gold leaves raw in the canonical escapes RDFC-1.0 hashes.
func escapeControls(nquads string) string {
	if nquads == "" {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(nquads, "\n"), "\n")
	for i, line := range lines {
		var b strings.Builder
		for _, r := range line {
			switch {
			case r == 0x08:
				b.WriteString(`\b`)
			case r == 0x0c:
				b.WriteString(`\f`)
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(&b, `\u%04X`, r)
			default:
				b.WriteRune(r)
			}
		}
		lines[i] = b.String()
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func requireAbsolute(v interface{}) error {
	switch t := v.(type) {
	case []interface{}:
		for _, e := range t {
			if err := requireAbsolute(e); err != nil {
				return err
			}
		}
	case map[string]interface{}:
		for k, val := range t {
			switch k {
			case "@id":
				if s, ok := val.(string); ok && !ld.IsAbsoluteIri(s) {
					return fmt.Errorf("%w: @id %q is not an absolute IRI (it would be dropped from the signed RDF)", ErrLinkedData, s)
				}
			case "@type":
				types, _ := val.([]interface{})
				for _, ty := range types {
					if s, ok := ty.(string); ok && !ld.IsAbsoluteIri(s) {
						return fmt.Errorf("%w: @type %q is not an absolute IRI", ErrLinkedData, s)
					}
				}
			}
			if err := requireAbsolute(val); err != nil {
				return err
			}
		}
	}
	return nil
}

func refusePoison(dataset *ld.RDFDataset) error {
	sigsOf := map[string][]string{}
	neighbours := map[string]map[string]bool{}
	sig := func(n ld.Node, self string) string {
		switch v := n.(type) {
		case ld.BlankNode:
			if v.Attribute == self {
				return "_:a"
			}
			return "_:z"
		case ld.IRI:
			return "<" + v.Value + ">"
		case ld.Literal:
			return fmt.Sprintf("%q^^%s@%s", v.Value, v.Datatype, v.Language)
		}
		return ""
	}
	for _, quads := range dataset.Graphs {
		for _, q := range quads {
			var blanks []string
			for _, n := range []ld.Node{q.Subject, q.Object, q.Graph} {
				if b, ok := n.(ld.BlankNode); ok {
					blanks = append(blanks, b.Attribute)
					sigsOf[b.Attribute] = append(sigsOf[b.Attribute], sig(q.Subject, b.Attribute)+" "+sig(q.Predicate, b.Attribute)+" "+sig(q.Object, b.Attribute)+" "+sig(q.Graph, b.Attribute))
				}
			}
			for _, a := range blanks {
				for _, b := range blanks {
					if a != b {
						if neighbours[a] == nil {
							neighbours[a] = map[string]bool{}
						}
						neighbours[a][b] = true
					}
				}
			}
		}
	}
	joined := map[string]string{}
	for node, sigs := range sigsOf {
		sort.Strings(sigs)
		joined[node] = strings.Join(sigs, "\x00")
	}
	for node, adjacent := range neighbours {
		same := 0
		for other := range adjacent {
			if joined[other] == joined[node] {
				same++
			}
		}
		if same > MaxSymmetricNeighbours {
			return fmt.Errorf("%w: poison graph, a blank node has %d indistinguishable neighbours (limit %d)", ErrLinkedData, same, MaxSymmetricNeighbours)
		}
	}
	return nil
}

func hasContext(ctx []string, want string) bool {
	for _, c := range ctx {
		if c == want {
			return true
		}
	}
	return false
}

// isConformingEd25519Signature2020 reports whether the proof is read as the conforming suite: the type
// is Ed25519Signature2020 and the credential names the context that defines it.
func isConformingEd25519Signature2020(vc *credential.VerifiableCredential) bool {
	return vc.Proof != nil && vc.Proof.Type == "Ed25519Signature2020" && hasContext(vc.Context, Ed25519Suite2020Context)
}

// verifyEd25519Signature2020 checks the conforming proof of a credential against the issuer key the caller resolved.
func verifyEd25519Signature2020(vc *credential.VerifiableCredential, pub ed25519.PublicKey, extra []PinnedContext) error {
	p := vc.Proof
	if p.Challenge != "" || p.Domain != "" || p.Nonce != "" {
		return fmt.Errorf("%w: a credential proof carries no challenge, domain or nonce", ErrLinkedData)
	}
	unsigned := *vc
	unsigned.Proof = nil
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return verifyLinkedDataProof(doc, vc.Context, p, pub, extra, "assertionMethod")
}

// isConformingPresentation reports whether the holder proof is read as the conforming suite: the type is
// Ed25519Signature2020 and the presentation names the context that defines it.
func isConformingPresentation(vp *credential.VerifiablePresentation) bool {
	return vp.Proof != nil && vp.Proof.Type == "Ed25519Signature2020" && hasContext(vp.Context, Ed25519Suite2020Context)
}

// verifyPresentationSignature2020 checks the conforming holder proof (proofPurpose authentication, challenge, domain and
// nonce inside the signed configuration) against the holder key the caller resolved.
func verifyPresentationSignature2020(vp *credential.VerifiablePresentation, pub ed25519.PublicKey, extra []PinnedContext) error {
	unsigned := *vp
	unsigned.Proof = nil
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return verifyLinkedDataProof(doc, vp.Context, vp.Proof, pub, extra, "authentication")
}

// verifyLinkedDataProof is the shared Ed25519Signature2020 check over a document without its proof.
func verifyLinkedDataProof(doc map[string]interface{}, contexts []string, p *credential.Proof, pub ed25519.PublicKey, extra []PinnedContext, purpose string) error {
	if p.ProofPurpose != purpose {
		return fmt.Errorf("%w: proofPurpose is %q, this proof needs %s", ErrLinkedData, p.ProofPurpose, purpose)
	}
	if _, err := time.Parse(time.RFC3339, p.Created); err != nil {
		return fmt.Errorf("%w: created %q is not an xsd:dateTime", ErrLinkedData, p.Created)
	}
	sig, err := decodeProofValue(p.ProofValue)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: proofValue decodes to %d bytes", ErrLinkedData, len(sig))
	}
	loader, err := newPinnedLoader(extra)
	if err != nil {
		return err
	}
	ctx := make([]interface{}, len(contexts))
	for i, c := range contexts {
		ctx[i] = c
	}
	cfg := map[string]interface{}{
		"@context": ctx, "type": "Ed25519Signature2020", "created": p.Created,
		"verificationMethod": p.VerificationMethod, "proofPurpose": p.ProofPurpose,
	}
	for k, v := range map[string]string{"challenge": p.Challenge, "domain": p.Domain, "nonce": p.Nonce} {
		if v != "" {
			cfg[k] = v
		}
	}
	canonDoc, err := canonicalize(doc, loader)
	if err != nil {
		return err
	}
	canonCfg, err := canonicalize(cfg, loader)
	if err != nil {
		return err
	}
	d, c := sha256.Sum256([]byte(canonDoc)), sha256.Sum256([]byte(canonCfg))
	if !ed25519.Verify(pub, append(c[:], d[:]...), sig) {
		return fmt.Errorf("%w: signature does not verify against the issuer key", ErrLinkedData)
	}
	return nil
}
