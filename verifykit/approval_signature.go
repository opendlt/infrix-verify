// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/opendlt/infrix-schema/evidence"
)

// THE APPROVAL SIGNATURE CHECK (brief 28bd row 1, L2992).
//
// Governance level G1 ("threshold approved") used to be credited on a non-zero plan hash and a non-empty identity string: an
// approval the node merely LISTED. It is now credited only when every approval in the bundle carries a signature this verifier
// checks itself, over the approval preimage the signer signed, under the scheme the approval declares, and the preimage commits to
// the plan the package proves. Nothing the node wrote beside the signature is credited: the plan hash, stage, identity, role, key
// page and key are read out of the SIGNED preimage and must equal the fields the approval states.
//
// The schemes are the ones a key page holds that this verifier can check without trusting anyone: the original bare Ed25519 form,
// and the Accumulate user signatures ed25519, btc (secp256k1, SHA-256, DER) and eth (secp256k1, raw r||s[||v], low s), each over
// sha256(metadataHash || sha256(preimage)) exactly as Accumulate's executor verifies them. An approval made with another type
// (legacyED25519, rcd1, btcLegacy, rsaSha256, ecdsaSha256) is not checkable here and so is not credited: the bundle caps at G0
// with the type named. What a signature cannot show offline is that its key is on the key page at the time it signed; that is the
// embedded Accumulate proof's job (row 3), and G1 does not claim it.

// approvalPreimageDomain is the domain tag every approval preimage opens with (pkg/workflow approvalSigningDomain).
const approvalPreimageDomain = "infrix/approval-signature/v2"

// approvalPreimageMaxField bounds a length-prefixed field, as the writer does.
const approvalPreimageMaxField = 1 << 20

// errApprovalUncheckable marks an approval this verifier cannot check (unsigned, or a scheme it does not implement): it is not a
// forgery, it is not evidence, and it caps the bundle at G0 without failing the package.
var errApprovalUncheckable = errors.New("approval cannot be checked")

// approvalPreimage is the decoded approval preimage: the fields a verifier binds the approval's stated fields to.
type approvalPreimage struct {
	NetworkID      string
	WorkflowID     string
	StageID        string
	PlanHash       [32]byte
	SignerIdentity string
	SignerRole     string
	KeyPageRef     string
	PublicKey      []byte
	// UserSignature is true when the preimage carries the user-signature section (an accumulate-* scheme).
	UserSignature      bool
	SignatureType      string
	SignerVersion      uint64
	SignatureTimestamp uint64
}

type preimageReader struct {
	b   []byte
	err error
}

func (r *preimageReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = fmt.Errorf("approval preimage is truncated")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *preimageReader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (r *preimageReader) str() string {
	n := r.take(4)
	if n == nil {
		return ""
	}
	l := binary.BigEndian.Uint32(n)
	if l > approvalPreimageMaxField {
		r.err = fmt.Errorf("approval preimage field of %d bytes exceeds the limit", l)
		return ""
	}
	return string(r.take(int(l)))
}

func (r *preimageReader) bytes32() (out [32]byte) {
	copy(out[:], r.take(32))
	return out
}

func (r *preimageReader) strList() {
	n := r.u64()
	if n > approvalPreimageMaxField {
		r.err = fmt.Errorf("approval preimage list of %d items exceeds the limit", n)
		return
	}
	prev := ""
	for i := uint64(0); i < n && r.err == nil; i++ {
		s := r.str()
		// the writer sorts a list; an unsorted one is not a preimage the writer produced
		if i > 0 && s < prev {
			r.err = fmt.Errorf("approval preimage list is not sorted")
		}
		prev = s
	}
}

// decodeApprovalPreimage reads a preimage in the exact field order pkg/workflow.TypedApproval.SigningPreimage writes, and refuses
// any byte it did not account for.
func decodeApprovalPreimage(b []byte) (*approvalPreimage, error) {
	r := &preimageReader{b: b}
	if d := r.str(); r.err == nil && d != approvalPreimageDomain {
		return nil, fmt.Errorf("approval preimage domain is %q, want %q", d, approvalPreimageDomain)
	}
	p := &approvalPreimage{}
	p.NetworkID = r.str()
	p.WorkflowID = r.str()
	p.StageID = r.str()
	p.PlanHash = r.bytes32()
	_ = r.bytes32() // SimulationHash
	_ = r.str()     // GhostReceiptID
	_ = r.str()     // Scope.ContractURL
	r.strList()     // Scope.Functions
	_ = r.u64()     // Scope.MaxAmount
	_ = r.u64()     // Scope.MaxGas
	r.strList()     // Scope.TargetAssets
	_ = r.u64()     // Conditions.MinBlockHeight
	_ = r.u64()     // Conditions.MaxBlockHeight
	_ = r.str()     // Conditions.RequiredState
	_ = r.u64()     // ExpiresAtBlock
	p.SignerIdentity = r.str()
	p.SignerRole = r.str()
	p.KeyPageRef = r.str()
	p.PublicKey = []byte(r.str())
	if r.err == nil && len(r.b) > 0 {
		if tag := r.str(); r.err == nil && tag != "user-signature" {
			return nil, fmt.Errorf("approval preimage carries an unknown trailing section %q", tag)
		}
		p.UserSignature = true
		p.SignatureType = r.str()
		p.SignerVersion = r.u64()
		p.SignatureTimestamp = r.u64()
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("approval preimage has %d unaccounted trailing byte(s)", len(r.b))
	}
	return p, nil
}

// verifyApprovalSignature checks one approval: its signature verifies over its preimage under its declared scheme, and the preimage
// commits to planHash and to every field the approval states. It returns errApprovalUncheckable (wrapped) for an approval that
// carries no signature or declares a scheme this verifier does not implement, and any other error for a signature or binding that
// is wrong.
func verifyApprovalSignature(ae evidence.ApprovalEvidenceRef, planHash [32]byte) error {
	if len(ae.Signature) == 0 && len(ae.SignedPreimage) == 0 && ae.SigType == "" {
		return fmt.Errorf("%w: it carries no signature", errApprovalUncheckable)
	}
	if len(ae.Signature) == 0 || len(ae.SignedPreimage) == 0 || len(ae.PublicKey) == 0 || ae.SigType == "" || ae.SignerPage == "" {
		return fmt.Errorf("the approval's signature is incomplete (signature, signed preimage, public key, scheme and key page are all required)")
	}
	pre, err := decodeApprovalPreimage(ae.SignedPreimage)
	if err != nil {
		return err
	}
	switch {
	case pre.PlanHash != planHash:
		return fmt.Errorf("the signed preimage approves plan %x, the package proves plan %x", pre.PlanHash, planHash)
	case pre.PlanHash != ae.PlanHash:
		return fmt.Errorf("the approval states plan %x, its signed preimage approves %x", ae.PlanHash, pre.PlanHash)
	case pre.StageID != ae.StageID:
		return fmt.Errorf("the approval states stage %q, its signed preimage names %q", ae.StageID, pre.StageID)
	case pre.SignerIdentity != ae.Identity:
		return fmt.Errorf("the approval states identity %q, its signed preimage names %q", ae.Identity, pre.SignerIdentity)
	case pre.SignerRole != ae.Role:
		return fmt.Errorf("the approval states role %q, its signed preimage names %q", ae.Role, pre.SignerRole)
	case pre.KeyPageRef != ae.SignerPage:
		return fmt.Errorf("the approval states key page %q, its signed preimage names %q", ae.SignerPage, pre.KeyPageRef)
	case !bytes.Equal(pre.PublicKey, ae.PublicKey):
		return fmt.Errorf("the approval's public key is not the key its signed preimage binds")
	}

	if ae.SigType == evidence.ApprovalSigTypeInfrixEd25519 {
		if pre.UserSignature {
			return fmt.Errorf("the approval declares %s, its signed preimage is a %q user signature", ae.SigType, pre.SignatureType)
		}
		if len(ae.PublicKey) != ed25519.PublicKeySize || len(ae.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("an %s approval needs a %d-byte key and a %d-byte signature", ae.SigType, ed25519.PublicKeySize, ed25519.SignatureSize)
		}
		if !ed25519.Verify(ed25519.PublicKey(ae.PublicKey), ae.SignedPreimage, ae.Signature) {
			return fmt.Errorf("the %s signature does not verify over the signed preimage", ae.SigType)
		}
		return nil
	}

	accType, ok := strings.CutPrefix(ae.SigType, evidence.ApprovalSigTypeAccumulatePrefix)
	if !ok {
		return fmt.Errorf("%w: it declares the unknown scheme %q", errApprovalUncheckable, ae.SigType)
	}
	if !pre.UserSignature || pre.SignatureType != accType {
		return fmt.Errorf("the approval declares %s, its signed preimage does not bind that user-signature type", ae.SigType)
	}
	if len(ae.SignatureMetadataHash) != sha256.Size {
		return fmt.Errorf("an %s approval needs its %d-byte signature metadata hash", ae.SigType, sha256.Size)
	}
	approvalHash := sha256.Sum256(ae.SignedPreimage)
	// Accumulate's verifySig: the signed message is metadataHash || messageHash, hashed once with SHA-256.
	msg := append(append([]byte(nil), ae.SignatureMetadataHash...), approvalHash[:]...)
	digest := sha256.Sum256(msg)
	switch accType {
	case "ed25519":
		if len(ae.PublicKey) != ed25519.PublicKeySize || len(ae.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("an %s approval needs a %d-byte key and a %d-byte signature", ae.SigType, ed25519.PublicKeySize, ed25519.SignatureSize)
		}
		if !ed25519.Verify(ed25519.PublicKey(ae.PublicKey), digest[:], ae.Signature) {
			return fmt.Errorf("the %s signature does not verify", ae.SigType)
		}
		return nil
	case "btc":
		pk, err := secp256k1.ParsePubKey(ae.PublicKey)
		if err != nil {
			return fmt.Errorf("the %s public key does not parse: %v", ae.SigType, err)
		}
		sig, err := secpecdsa.ParseDERSignature(ae.Signature)
		if err != nil {
			return fmt.Errorf("the %s signature is not strict DER: %v", ae.SigType, err)
		}
		if !sig.Verify(digest[:], pk) {
			return fmt.Errorf("the %s signature does not verify", ae.SigType)
		}
		return nil
	case "eth":
		pk, err := secp256k1.ParsePubKey(ae.PublicKey)
		if err != nil {
			return fmt.Errorf("the %s public key does not parse: %v", ae.SigType, err)
		}
		if len(ae.Signature) != 64 && len(ae.Signature) != 65 {
			return fmt.Errorf("an %s signature is 64 or 65 bytes (r||s[||v]), got %d", ae.SigType, len(ae.Signature))
		}
		var r, s secp256k1.ModNScalar
		if overflow := r.SetByteSlice(ae.Signature[:32]); overflow || r.IsZero() {
			return fmt.Errorf("the %s signature's r is out of range", ae.SigType)
		}
		if overflow := s.SetByteSlice(ae.Signature[32:64]); overflow || s.IsZero() {
			return fmt.Errorf("the %s signature's s is out of range", ae.SigType)
		}
		// Accumulate verifies an eth signature with go-ethereum's VerifySignature, which refuses the malleable upper-half s.
		if s.IsOverHalfOrder() {
			return fmt.Errorf("the %s signature has a malleable upper-half s", ae.SigType)
		}
		if !secpecdsa.NewSignature(&r, &s).Verify(digest[:], pk) {
			return fmt.Errorf("the %s signature does not verify", ae.SigType)
		}
		return nil
	}
	return fmt.Errorf("%w: the Accumulate %q signature type is not one this verifier checks (ed25519, btc, eth)", errApprovalUncheckable, accType)
}

// approvalsVerdict checks every approval in the bundle against planHash. signed is true only when there is at least one approval
// and every one verified; failures are approvals whose signature or binding is wrong (forged or tampered), uncheckable ones are
// unsigned or in a scheme this verifier does not implement.
type approvalsVerdict struct {
	Count       int
	Signed      bool
	Failures    []string
	Uncheckable []string
}

func checkApprovalSignatures(bundle *evidence.EvidenceBundle, planHash [32]byte) approvalsVerdict {
	v := approvalsVerdict{Count: len(bundle.ApprovalEvidence)}
	for i, ae := range bundle.ApprovalEvidence {
		if err := verifyApprovalSignature(ae, planHash); err != nil {
			line := fmt.Sprintf("approval %d (%s): %v", i, ae.Identity, err)
			if errors.Is(err, errApprovalUncheckable) {
				v.Uncheckable = append(v.Uncheckable, line)
			} else {
				v.Failures = append(v.Failures, line)
			}
		}
	}
	v.Signed = v.Count > 0 && len(v.Failures) == 0 && len(v.Uncheckable) == 0
	return v
}
