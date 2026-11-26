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
	"sort"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	evidence "github.com/opendlt/infrix-schema/evidence"
)

// testApproval is the signed content of one approval, written by a TEST-SIDE preimage encoder. The decoder under test is held to
// the node's own bytes separately (TestApprovalPreimageDecoderReadsTheNodesSharedVector); this encoder only lets the tests sign.
type testApproval struct {
	NetworkID, WorkflowID, StageID string
	PlanHash, SimulationHash       [32]byte
	GhostReceiptID, ContractURL    string
	Functions, TargetAssets        []string
	MaxAmount, MaxGas              uint64
	MinBlock, MaxBlock             uint64
	RequiredState                  string
	ExpiresAtBlock                 uint64
	Identity, Role, KeyPage        string
	PublicKey                      []byte
	SignatureType                  string // empty: the bare form
	SignerVersion, Timestamp       uint64
}

func (a testApproval) preimage() []byte {
	var b bytes.Buffer
	str := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		b.Write(n[:])
		b.WriteString(s)
	}
	u64 := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		b.Write(n[:])
	}
	list := func(items []string) {
		s := append([]string(nil), items...)
		sort.Strings(s)
		u64(uint64(len(s)))
		for _, it := range s {
			str(it)
		}
	}
	str(approvalPreimageDomain)
	str(a.NetworkID)
	str(a.WorkflowID)
	str(a.StageID)
	b.Write(a.PlanHash[:])
	b.Write(a.SimulationHash[:])
	str(a.GhostReceiptID)
	str(a.ContractURL)
	list(a.Functions)
	u64(a.MaxAmount)
	u64(a.MaxGas)
	list(a.TargetAssets)
	u64(a.MinBlock)
	u64(a.MaxBlock)
	str(a.RequiredState)
	u64(a.ExpiresAtBlock)
	str(a.Identity)
	str(a.Role)
	str(a.KeyPage)
	str(string(a.PublicKey))
	if a.SignatureType != "" {
		str("user-signature")
		str(a.SignatureType)
		u64(a.SignerVersion)
		u64(a.Timestamp)
	}
	return b.Bytes()
}

// fixture keys, deterministic so a failure reproduces
func testEd25519Key(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testSecpKey(seed byte) *secp256k1.PrivateKey {
	return secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{seed}, 32))
}

var testMetadataHash = sha256.Sum256([]byte("accumulate signature metadata (test)"))

// signedApproval returns an ApprovalEvidenceRef for planHash signed under scheme (an evidence.ApprovalSigType* value).
func signedApproval(t *testing.T, scheme string, planHash [32]byte) evidence.ApprovalEvidenceRef {
	t.Helper()
	a := testApproval{
		NetworkID: "kermit", WorkflowID: "intent-vk", StageID: "s1", PlanHash: planHash,
		ContractURL: "acc://app.acme/escrow", Functions: []string{"release"}, MaxGas: 250_000,
		Identity: "acc://approver.acme", Role: "approver", KeyPage: "acc://approver.acme/book/1",
	}
	ref := evidence.ApprovalEvidenceRef{StageID: a.StageID, Identity: a.Identity, Role: a.Role, PlanHash: planHash, SigType: scheme, SignerPage: a.KeyPage}
	accDigest := func(pre []byte) [32]byte {
		h := sha256.Sum256(pre)
		return sha256.Sum256(append(append([]byte(nil), testMetadataHash[:]...), h[:]...))
	}
	switch scheme {
	case evidence.ApprovalSigTypeInfrixEd25519:
		k := testEd25519Key(1)
		a.PublicKey = k.Public().(ed25519.PublicKey)
		ref.SignedPreimage = a.preimage()
		ref.Signature = ed25519.Sign(k, ref.SignedPreimage)
	case evidence.ApprovalSigTypeAccumulatePrefix + "ed25519":
		k := testEd25519Key(2)
		a.PublicKey = k.Public().(ed25519.PublicKey)
		a.SignatureType, a.SignerVersion, a.Timestamp = "ed25519", 3, 1_700_000_000_000_000
		ref.SignedPreimage = a.preimage()
		d := accDigest(ref.SignedPreimage)
		ref.Signature = ed25519.Sign(k, d[:])
		ref.SignatureMetadataHash = testMetadataHash[:]
	case evidence.ApprovalSigTypeAccumulatePrefix + "btc":
		k := testSecpKey(3)
		a.PublicKey = k.PubKey().SerializeCompressed()
		a.SignatureType, a.SignerVersion, a.Timestamp = "btc", 3, 1_700_000_000_000_001
		ref.SignedPreimage = a.preimage()
		d := accDigest(ref.SignedPreimage)
		ref.Signature = secpecdsa.Sign(k, d[:]).Serialize()
		ref.SignatureMetadataHash = testMetadataHash[:]
	case evidence.ApprovalSigTypeAccumulatePrefix + "eth":
		k := testSecpKey(4)
		a.PublicKey = k.PubKey().SerializeUncompressed()
		a.SignatureType, a.SignerVersion, a.Timestamp = "eth", 3, 1_700_000_000_000_002
		ref.SignedPreimage = a.preimage()
		d := accDigest(ref.SignedPreimage)
		compact := secpecdsa.SignCompact(k, d[:], false) // v || r || s, s already low
		ref.Signature = append(append([]byte(nil), compact[1:]...), compact[0]-27)
		ref.SignatureMetadataHash = testMetadataHash[:]
	default:
		t.Fatalf("no fixture signer for scheme %q", scheme)
	}
	ref.PublicKey = a.PublicKey
	return ref
}
