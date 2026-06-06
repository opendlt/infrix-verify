// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package witness is the independent witness network (platform-review-3
// Epic 5). A witness does NOT execute the original intent. It fetches a
// published proof bundle, fetches the Accumulate L0 anchor, verifies the
// evidence, replays the capsule, compares the re-derived outcome, and —
// if everything reproduces — signs a WitnessReceipt with its own key.
//
// Witness receipts answer the "operator software with receipts" objection:
// the same outcome is independently reproduced and attested by parties
// other than the node that produced it. A verifier that collects enough
// receipts from distinct witnesses has cross-checked the operation against
// an independent quorum, not just the producing node.
//
// This package is a leaf: it defines the receipt schema, signing, and the
// pure cross-binding/threshold evaluation. The runner that actually drives
// verification + replay (which imports verifykit) lives in the CLI so this
// package can be imported by verifykit without an import cycle.
package witness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// ReceiptVersion is the wire version of the witness receipt schema.
const ReceiptVersion = "1"

// Replay result strings recorded on a receipt.
const (
	ReplayReproduced  = "reproduced"
	ReplayDiverged    = "diverged"
	ReplayUnavailable = "unavailable"
)

// Receipt is one witness's independent attestation that it reproduced a
// proof bundle's outcome. The signature covers every field except
// Signature itself; PublicKey carries the Ed25519 key so a verifier can
// check the signature offline (the WitnessKeyPage is the L0 identity the
// key is expected to be bound to).
type Receipt struct {
	ReceiptVersion string `json:"receiptVersion"`

	// WitnessIdentity is the witness's ADI / identity string.
	WitnessIdentity string `json:"witnessIdentity"`
	// WitnessKeyPage is the L0 key page the signing key is bound to.
	WitnessKeyPage string `json:"witnessKeyPage"`
	// RuntimeVersion is the witness runtime that performed the replay.
	RuntimeVersion string `json:"runtimeVersion"`

	// ReplayCapsuleHash binds the receipt to the exact replay capsule the
	// witness replayed (sha256 of the capsule bytes).
	ReplayCapsuleHash string `json:"replayCapsuleHash"`
	// OutcomeHash is the bundle outcome digest the witness reproduced.
	OutcomeHash string `json:"outcomeHash"`
	// L0AnchorTxHash binds the receipt to the L0 anchor the witness
	// fetched (empty for unanchored bundles).
	L0AnchorTxHash string `json:"l0AnchorTxHash,omitempty"`

	// ReplayResult is reproduced / diverged / unavailable.
	ReplayResult string `json:"replayResult"`
	// Timestamp is the Unix second the witness signed the receipt.
	Timestamp int64 `json:"timestamp"`

	// PublicKey is the Ed25519 public key (carried for offline signature
	// verification).
	PublicKey []byte `json:"publicKey"`
	// Signature is the Ed25519 signature over SigningContent().
	Signature []byte `json:"signature"`
}

// SigningContent is the canonical byte sequence the signature covers:
// every field except Signature, length-framed so distinct receipts cannot
// collide.
func (r *Receipt) SigningContent() []byte {
	h := sha256.New()
	writeField(h, "version", []byte(r.ReceiptVersion))
	writeField(h, "identity", []byte(r.WitnessIdentity))
	writeField(h, "keyPage", []byte(r.WitnessKeyPage))
	writeField(h, "runtime", []byte(r.RuntimeVersion))
	writeField(h, "capsuleHash", []byte(r.ReplayCapsuleHash))
	writeField(h, "outcomeHash", []byte(r.OutcomeHash))
	writeField(h, "anchorTx", []byte(r.L0AnchorTxHash))
	writeField(h, "replayResult", []byte(r.ReplayResult))
	var tsbuf [8]byte
	binary.BigEndian.PutUint64(tsbuf[:], uint64(r.Timestamp))
	writeField(h, "timestamp", tsbuf[:])
	writeField(h, "publicKey", r.PublicKey)
	return h.Sum(nil)
}

// Sign signs the receipt with the given Ed25519 private key and records
// the corresponding public key.
func (r *Receipt) Sign(priv ed25519.PrivateKey) {
	r.ReceiptVersion = ReceiptVersion
	r.PublicKey = append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
	r.Signature = ed25519.Sign(priv, r.SigningContent())
}

// VerifySignature checks the receipt's self-signature.
func (r *Receipt) VerifySignature() error {
	if len(r.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: receipt has no/invalid public key")
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("witness: receipt has no/invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(r.PublicKey), r.SigningContent(), r.Signature) {
		return fmt.Errorf("witness: receipt signature does not verify")
	}
	return nil
}

// WitnessClockSkewSeconds is the tolerated forward clock skew for a witness
// receipt timestamp relative to the verifier's reference time.
const WitnessClockSkewSeconds = 300

// Expected carries the bundle facts a valid receipt must commit to.
type Expected struct {
	OutcomeHash       string // hex of the bundle OutcomeDigest
	ReplayCapsuleHash string // sha256 hex of the package replay capsule bytes
	L0AnchorTxHash    string // bundle anchor tx hash (empty when unanchored)

	// NowUnix is the verifier's reference time. When > 0 it enables the
	// freshness checks below (and the forward-skew guard); 0 disables them.
	NowUnix int64
	// MaxAgeSeconds, when > 0 (and NowUnix > 0), rejects receipts older than
	// this many seconds — an operator policy that a witness attestation must
	// be recent. 0 means no maximum age (archived proofs verify forever).
	MaxAgeSeconds int64
}

// KeyPageAuthorization is the result of confirming a witness's signing key is
// authorized on the witness's declared L0 key page.
type KeyPageAuthorization struct {
	// Authorized is true when the witness public key's hash is a current key
	// on the declared key page.
	Authorized bool
	// Revoked is true when the key page exists but the witness key is NOT on
	// it (the page was found, the key was removed/never present) — a stronger,
	// more actionable signal than a bare lookup failure.
	Revoked bool
	// Detail is a human-readable explanation.
	Detail string
}

// KeyPageAuthorizer confirms that a witness's signing key is authorized on
// the witness's declared L0 key page. A live implementation queries L0; the
// witness package stays a leaf by depending only on this interface.
type KeyPageAuthorizer interface {
	Authorize(keyPageURL string, publicKey []byte) (KeyPageAuthorization, error)
}

// CheckFreshness validates the receipt timestamp against exp's reference time.
func (r *Receipt) CheckFreshness(exp Expected) error {
	if exp.NowUnix <= 0 {
		return nil
	}
	if r.Timestamp > exp.NowUnix+WitnessClockSkewSeconds {
		return fmt.Errorf("witness: receipt timestamp %d is in the future (now=%d, skew=%ds)", r.Timestamp, exp.NowUnix, WitnessClockSkewSeconds)
	}
	if exp.MaxAgeSeconds > 0 && exp.NowUnix-r.Timestamp > exp.MaxAgeSeconds {
		return fmt.Errorf("witness: receipt is stale (age %ds exceeds max %ds)", exp.NowUnix-r.Timestamp, exp.MaxAgeSeconds)
	}
	return nil
}

// Validate checks a single receipt against the expected bundle facts: the
// signature verifies, the replay reproduced, and every cross-binding hash
// matches. Returns nil when the receipt is a valid independent attestation.
func (r *Receipt) Validate(exp Expected) error {
	if r.ReceiptVersion != ReceiptVersion {
		return fmt.Errorf("witness: unsupported receipt version %q", r.ReceiptVersion)
	}
	if err := r.VerifySignature(); err != nil {
		return err
	}
	if r.ReplayResult != ReplayReproduced {
		return fmt.Errorf("witness: receipt replay result is %q (not %q)", r.ReplayResult, ReplayReproduced)
	}
	if r.OutcomeHash != exp.OutcomeHash {
		return fmt.Errorf("witness: receipt outcome hash does not match the bundle")
	}
	if exp.ReplayCapsuleHash != "" && r.ReplayCapsuleHash != exp.ReplayCapsuleHash {
		return fmt.Errorf("witness: receipt replay-capsule hash does not match the bundle")
	}
	if exp.L0AnchorTxHash != "" && r.L0AnchorTxHash != exp.L0AnchorTxHash {
		return fmt.Errorf("witness: receipt L0 anchor tx hash does not match the bundle")
	}
	if r.WitnessIdentity == "" {
		return fmt.Errorf("witness: receipt has no witness identity")
	}
	if r.WitnessKeyPage == "" {
		return fmt.Errorf("witness: receipt has no witness key page")
	}
	return r.CheckFreshness(exp)
}

// Evaluation is the outcome of checking a set of receipts against a bundle.
type Evaluation struct {
	// ValidCount is the number of valid receipts from DISTINCT witness
	// identities (duplicates collapse to one and are reported).
	ValidCount int
	// DistinctIdentities lists the accepted witness identities.
	DistinctIdentities []string
	// DuplicateIdentities lists identities that appeared more than once
	// (only the first is counted).
	DuplicateIdentities []string
	// Rejected maps a receipt index to why it was rejected.
	Rejected map[int]string
}

// Evaluate validates every receipt against the expected bundle facts,
// deduplicates by witness identity (a witness cannot vote twice), and
// reports the count of distinct valid witnesses. platform-review-3 Epic 5.
// This is the offline form (Ed25519 + cross-binding + freshness only); use
// EvaluateAuthorized to additionally require live L0 key-page authorization.
func Evaluate(receipts []Receipt, exp Expected) Evaluation {
	return EvaluateAuthorized(receipts, exp, nil)
}

// EvaluateAuthorized is Evaluate plus, when authorizer is non-nil, a hard
// requirement that each receipt's signing key is authorized on its declared
// L0 key page (and not revoked). A receipt that passes every offline check
// but whose key page does not authorize its key — or whose key was removed
// (revoked) — is rejected and does NOT count toward the threshold. This is
// what makes a witness meaningfully independent: possession of an Ed25519 key
// is not enough; the key must be a live, authorized member of the witness's
// L0 identity. A key-page lookup ERROR is fail-closed (the receipt is
// rejected) so a witness cannot be counted while its authorization is unknown.
func EvaluateAuthorized(receipts []Receipt, exp Expected, authorizer KeyPageAuthorizer) Evaluation {
	ev := Evaluation{Rejected: map[int]string{}}
	seen := map[string]bool{}
	for i := range receipts {
		r := &receipts[i]
		if err := r.Validate(exp); err != nil {
			ev.Rejected[i] = err.Error()
			continue
		}
		if authorizer != nil {
			authz, err := authorizer.Authorize(r.WitnessKeyPage, r.PublicKey)
			switch {
			case err != nil:
				ev.Rejected[i] = "key-page authorization error (fail-closed): " + err.Error()
				continue
			case authz.Revoked:
				ev.Rejected[i] = "witness key revoked on key page " + r.WitnessKeyPage + ": " + authz.Detail
				continue
			case !authz.Authorized:
				ev.Rejected[i] = "witness key not authorized on key page " + r.WitnessKeyPage + ": " + authz.Detail
				continue
			}
		}
		if seen[r.WitnessIdentity] {
			ev.DuplicateIdentities = append(ev.DuplicateIdentities, r.WitnessIdentity)
			ev.Rejected[i] = "duplicate witness identity " + r.WitnessIdentity
			continue
		}
		seen[r.WitnessIdentity] = true
		ev.DistinctIdentities = append(ev.DistinctIdentities, r.WitnessIdentity)
		ev.ValidCount++
	}
	sort.Strings(ev.DistinctIdentities)
	return ev
}

// ThresholdMet reports whether the evaluation meets a minimum witness
// count. A threshold of 0 is always met.
func (e Evaluation) ThresholdMet(minWitnesses int) bool {
	return e.ValidCount >= minWitnesses
}

// HashBytes is the canonical sha256-hex of arbitrary bytes (used to
// commit to the replay capsule).
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeField(h interface{ Write([]byte) (int, error) }, _ string, v []byte) {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(v)))
	_, _ = h.Write(lenbuf[:])
	_, _ = h.Write(v)
}
