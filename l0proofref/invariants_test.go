// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proofref/capture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	. "gitlab.com/accumulatenetwork/accumulate/test/harness"
	. "gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
	acctesting "gitlab.com/accumulatenetwork/accumulate/test/testing"
)

// invariantSim is a simulator with an identity and two data accounts on one BVN: the anchor account and another account under the same book.
type invariantSim struct {
	sim            *Sim
	key            []byte
	book           *url.URL
	anchor, other  *url.URL
	timestamp      uint64
	identityParent *url.URL
}

func newInvariantSim(t *testing.T) *invariantSim {
	key := acctesting.GenerateKey("l0proof", "invariant-key")
	alice := protocol.AccountUrl("l0proof-invariants")
	s := &invariantSim{key: key, book: alice.JoinPath("book", "1"), anchor: alice.JoinPath("anchors"), other: alice.JoinPath("other"), identityParent: alice}
	s.sim = NewSim(t, simulator.SimpleNetwork("l0proof-invariants", 1, 1), simulator.Genesis(GenesisTime))
	MakeIdentity(t, s.sim.DatabaseFor(alice), alice, key[32:])
	CreditCredits(t, s.sim.DatabaseFor(alice), s.book, 1e9)
	for _, u := range []*url.URL{s.anchor, s.other} {
		da := &protocol.DataAccount{Url: u}
		da.AddAuthority(alice.JoinPath("book"))
		MakeAccount(t, s.sim.DatabaseFor(alice), da)
	}
	s.sim.StepN(5)
	return s
}

func (s *invariantSim) tx(principal *url.URL, body protocol.TransactionBody) build.SignatureBuilder {
	s.timestamp++
	return build.Transaction().For(principal).Body(body).SignWith(s.book).Version(1).Timestamp(s.timestamp).PrivateKey(s.key)
}

// onMainChain asks Accumulate's own API whether hash is an entry of account's main chain.
func (s *invariantSim) onMainChain(t *testing.T, account *url.URL, hash []byte) bool {
	t.Helper()
	_, err := s.sim.Query().Query(context.Background(), account, &api.ChainQuery{Name: "main", Entry: hash})
	if err == nil {
		return true
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Fatalf("query %s main chain for %X: %v", account, hash, err)
	}
	return false
}

// refusal submits a transaction and returns Accumulate's refusal: the submission's own error, or the execution failure.
func (s *invariantSim) refusal(t *testing.T, b build.SignatureBuilder) (string, []byte) {
	t.Helper()
	env, err := b.Done()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	txn := env.Transaction[0]
	for _, st := range s.sim.Submit(env) {
		if st.TxID.Hash() == txn.ID().Hash() && st.Error != nil {
			return st.Error.Error(), txn.GetHash()
		}
	}
	var st *protocol.TransactionStatus
	s.sim.StepUntil(Txn(txn.ID()).Capture(&st).Fails())
	if st == nil || st.Error == nil {
		t.Fatalf("the transaction failed with no error recorded")
	}
	return st.Error.Error(), txn.GetHash()
}

// Ruling 3 (brief 28bi), DF against Accumulate's executor on the simulator: the anchor account is bound by the transaction header's principal
// plus the protocol rule that a transaction's hash goes on its principal's main chain only when it executes successfully.
//
//   - A WriteData that executes is on its principal's main chain and on no other account's; the hash and principal l0proof recomputes from the
//     exact header and body are Accumulate's, and an entry path to the partition root is captured for it.
//   - A WriteData to the same principal that FAILS execution (writing scratch data to account state, refused by the executor in
//     internal/core/execute/v2/chain/write_data.go) is NOT on the principal's main chain, so no entry path exists for it: a proof cannot be
//     built from a transaction Accumulate did not execute.
//
// Bite: the failed transaction's principal is the anchor account, so the only thing keeping it off the chain is the executor's rule.
func TestDF_AnchorAccountIsBoundByPrincipalAndExecution(t *testing.T) {
	s := newInvariantSim(t)
	leaf := sha256.Sum256([]byte("anchor-binding batch root"))
	good := s.sim.BuildAndSubmitTxnSuccessfully(s.tx(s.anchor, &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{leaf[:]}}}))
	s.sim.StepUntil(Txn(good.TxID).Succeeds())
	h := good.TxID.Hash()
	if !s.onMainChain(t, s.anchor, h[:]) {
		t.Fatal("an executed WriteData is not on its principal's main chain")
	}
	if s.onMainChain(t, s.other, h[:]) {
		t.Fatal("an executed WriteData is on an account that is not its principal")
	}
	a, _, err := capture.TxEntry(context.Background(), s.sim.Query(), good.TxID)
	if err != nil {
		t.Fatalf("capture the executed transaction: %v", err)
	}
	gotHash, principal, err := a.Chain.Transaction.Hash(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(principal, s.anchor.String()) || string(gotHash) != string(h[:]) {
		t.Fatalf("l0proof reads principal %s hash %X; Accumulate executed %s on %s", principal, gotHash, good.TxID, s.anchor)
	}

	why, failedHash := s.refusal(t, s.tx(s.anchor, &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{leaf[:]}}, WriteToState: true, Scratch: true}))
	if !strings.Contains(why, "scratch") {
		t.Fatalf("the executor refused for another reason: %s", why)
	}
	if s.onMainChain(t, s.anchor, failedHash) {
		t.Fatal("a transaction that failed execution is on its principal's main chain: the anchor-account binding does not hold")
	}
	failedID := s.anchor.WithTxID(*(*[32]byte)(failedHash))
	if _, _, err := capture.TxEntry(context.Background(), s.sim.Query(), failedID); err == nil {
		t.Fatal("an entry path was captured for a transaction Accumulate did not execute")
	}
}

// bodyOf64Bytes is a CreateDataAccount whose binary encoding is exactly 64 bytes, found by lengthening the account name, and the builder for
// it with Ignore64Byte set: Accumulate's own signature builder corrects a 64-byte body by default (pkg/build/signature.go), so a client of the
// library never sends one by accident; a hostile client builds it anyway, which is what the executor's check is for.
func bodyOf64Bytes(t *testing.T, s *invariantSim) (protocol.TransactionBody, build.SignatureBuilder) {
	for n := 1; n < 64; n++ {
		b := &protocol.CreateDataAccount{Url: s.identityParent.JoinPath(strings.Repeat("d", n))}
		data, err := b.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 64 {
			sb := s.tx(s.identityParent, b)
			sb.Ignore64Byte = true
			return b, sb
		}
	}
	t.Fatal("no CreateDataAccount encodes to 64 bytes")
	return nil, build.SignatureBuilder{}
}

// Ruling 5 (brief 28bi), DF against Accumulate on the simulator: paths carry no positions (l0proof.Path.Apply), and their soundness rests on
// every 64-byte preimage on a proof route being a pair of hashes the protocol computed. That holds because Accumulate refuses the only two
// ways a caller could place chosen 64 bytes, or a chosen single hash, where a node of a path sits:
//
//   - a transaction body of exactly 64 bytes: internal/core/execute/v2/block/msg_transaction.go TransactionMessage.check, "cannot process
//     transaction: body is 64 bytes long" (protocol/transaction_hash.go getBodyHash reports it);
//   - the single-hash AccumulateDataEntry, whose hash is SHA-256 of caller-chosen bytes: internal/core/execute/v2/chain/write_data.go
//     entryIsAccepted returns false for it ("data entries are not accepted"); the DoubleHashDataEntry and the Factom entry it accepts hash
//     their data again (protocol/data_entry.go), so a caller never chooses a path node's preimage.
//
// Bites: a 63- or 65-byte body of the same type is processed past that check, and the same data as a DoubleHashDataEntry executes.
func TestDF_AccumulateRefuses64ByteBodiesAndSingleHashEntries(t *testing.T) {
	s := newInvariantSim(t)

	_, sb := bodyOf64Bytes(t, s)
	env, err := sb.Done()
	if err != nil {
		t.Fatal(err)
	}
	if !env.Transaction[0].BodyIs64Bytes() {
		t.Fatal("the constructed body is not the 64-byte case Accumulate checks")
	}
	why, _ := s.refusal(t, sb)
	if !strings.Contains(why, "body is 64 bytes long") {
		t.Fatalf("a 64-byte body was not refused for its length: %s", why)
	}
	for _, name := range []string{"ab", strings.Repeat("e", 40)} {
		other := &protocol.CreateDataAccount{Url: s.identityParent.JoinPath(name)}
		env, err := s.tx(s.identityParent, other).Done()
		if err != nil {
			t.Fatal(err)
		}
		if env.Transaction[0].BodyIs64Bytes() {
			t.Fatalf("bite: %q is also 64 bytes", name)
		}
		st := s.sim.SubmitTxnSuccessfully(env)
		s.sim.StepUntil(Txn(st.TxID).Succeeds())
	}

	data := sha256.Sum256([]byte("a caller-chosen value"))
	why, single := s.refusal(t, s.tx(s.anchor, &protocol.WriteData{Entry: &protocol.AccumulateDataEntry{Data: [][]byte{data[:]}}}))
	if !strings.Contains(why, "not accepted") {
		t.Fatalf("a single-hash data entry was not refused as unaccepted: %s", why)
	}
	if s.onMainChain(t, s.anchor, single) {
		t.Fatal("the refused single-hash entry is on the anchor account's main chain")
	}
	st := s.sim.BuildAndSubmitTxnSuccessfully(s.tx(s.anchor, &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{data[:]}}}))
	s.sim.StepUntil(Txn(st.TxID).Succeeds())

	// l0proof itself never treats an entry as single-hash: it recomputes the double hash over the items, so a single-hash entry hash is not
	// what its transaction hash commits to.
	single1 := sha256.Sum256(data[:])
	double := sha256.Sum256(l0proof.MerkleRoot([][]byte{single1[:]}))
	if single1 == double {
		t.Fatal("the double hash equals the single hash")
	}
}
