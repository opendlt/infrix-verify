// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proofref_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/opendlt/infrix-verify/l0proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/bpt"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/keyvalue"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/keyvalue/memory"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/record"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DF-01: l0proof's receipt, merkle-state, BPT, transaction-hash and account-decoding rules agree with Accumulate's own implementation (the operator's
// fork, test-only here) on every captured fixture and on 10,000 randomised valid and invalid inputs. A disagreement in either direction fails.

func rnd32(r *rand.Rand) []byte {
	b := make([]byte, 32)
	r.Read(b)
	return b
}

func toPath(es []*merkle.ReceiptEntry) l0proof.Path {
	p := make(l0proof.Path, len(es))
	for i, e := range es {
		p[i] = l0proof.Step{Right: e.Right, Hash: append([]byte(nil), e.Hash...)}
	}
	return p
}

// agree compares Accumulate's strict receipt validation with l0proof's path fold for one receipt.
func agree(t *testing.T, what string, r *merkle.Receipt) bool {
	t.Helper()
	ref := r.Validate(nil)
	got, err := toPath(r.Entries).Apply(r.Start, 4096)
	mine := err == nil && bytes.Equal(got, r.Anchor)
	if ref != mine {
		t.Errorf("%s: Accumulate says %v, l0proof says %v (%v)", what, ref, mine, err)
	}
	return ref
}

// corrupt applies one of the invalid-input classes to a copy of the receipt.
func corrupt(r *rand.Rand, rc *merkle.Receipt) *merkle.Receipt {
	c := rc.Copy()
	switch k := r.Intn(5); {
	case k == 0 && len(c.Entries) > 0:
		c.Entries[r.Intn(len(c.Entries))].Hash[r.Intn(32)] ^= byte(1 + r.Intn(255))
	case k == 1 && len(c.Entries) > 0:
		e := c.Entries[r.Intn(len(c.Entries))]
		e.Right = !e.Right
	case k == 2 && len(c.Entries) > 0:
		c.Entries = c.Entries[:len(c.Entries)-1]
	case k == 3 && len(c.Entries) > 0:
		e := c.Entries[r.Intn(len(c.Entries))]
		e.Hash = append(e.Hash, 0) // a 33-byte entry: strict validation refuses it
	default:
		c.Start = rnd32(r)
	}
	return c
}

func TestDF01_AgreesWithAccumulateOnRandomisedInputs(t *testing.T) {
	r := rand.New(rand.NewSource(20261126))
	cases, valid, invalid := 0, 0, 0
	count := func(ok bool) {
		cases++
		if ok {
			valid++
		} else {
			invalid++
		}
	}

	// 4,000 merkle receipts and merkle-state roots over chains of 1..200 elements
	for i := 0; i < 2000; i++ {
		n := 1 + r.Intn(200)
		list := make([][]byte, n)
		for j := range list {
			list[j] = rnd32(r)
		}
		h := merkle.Hasher(list)
		if !bytes.Equal(l0proof.MerkleRoot(list), h.MerkleHash()) {
			t.Fatalf("merkle root of %d elements disagrees", n)
		}
		rc := h.Receipt(r.Intn(n), n-1)
		count(agree(t, fmt.Sprintf("receipt %d", i), rc))
		count(agree(t, fmt.Sprintf("corrupted receipt %d", i), corrupt(r, rc)))
	}

	// 2,000 BPT receipts from BPTs of 1..400 accounts
	for i := 0; i < 100; i++ {
		store := keyvalue.RecordStore{Store: memory.New(nil).Begin(nil, true)}
		b := bpt.New(nil, nil, store, record.NewKey("BPT", i))
		n := 1 + r.Intn(400)
		var keys []*record.Key
		for j := 0; j < n; j++ {
			k := record.KeyFromHash(*(*[32]byte)(rnd32(r)))
			keys = append(keys, k)
			if err := b.Insert(k, rnd32(r)); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.Commit(); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 10; j++ {
			rc, err := b.GetReceipt(keys[r.Intn(n)])
			if err != nil {
				t.Fatal(err)
			}
			count(agree(t, fmt.Sprintf("bpt %d/%d", i, j), rc))
			count(agree(t, fmt.Sprintf("corrupted bpt %d/%d", i, j), corrupt(r, rc)))
		}
	}

	// 2,000 WriteData transactions: the hash l0proof recomputes is Transaction.GetHash, and a mutated transaction never yields the original hash
	for i := 0; i < 1000; i++ {
		txn, wd := randomWriteData(r)
		header, err := txn.Header.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		noEntry := wd.Copy()
		noEntry.Entry = nil
		body, err := noEntry.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		tx := l0proof.WriteDataTx{Header: header, Body: body}
		for _, d := range wd.Entry.GetData() {
			tx.Entry = append(tx.Entry, d)
		}
		got, principal, err := tx.Hash(nil)
		if err != nil || !bytes.Equal(got, txn.GetHash()) || principal != txn.Header.Principal.String() {
			t.Fatalf("transaction %d: l0proof %X %s %v, Accumulate %X %s", i, got, principal, err, txn.GetHash(), txn.Header.Principal)
		}
		count(true)
		// mutate one byte of the header, the body or an item
		m := tx
		m.Header, m.Body = append(l0proof.Bytes(nil), header...), append(l0proof.Bytes(nil), body...)
		m.Entry = append([]l0proof.Bytes(nil), tx.Entry...)
		switch r.Intn(3) {
		case 0:
			m.Header[r.Intn(len(m.Header))] ^= 0x20
		case 1:
			m.Body = append(m.Body, 0x03, 0x01) // a scratch flag: refused
		default:
			k := r.Intn(len(m.Entry))
			m.Entry[k] = append(append(l0proof.Bytes(nil), m.Entry[k]...), 'x')
		}
		if h, _, err := m.Hash(nil); err == nil && bytes.Equal(h, txn.GetHash()) {
			t.Fatalf("mutated transaction %d still hashes to the original", i)
		}
		count(false)
	}

	// 2,000 account main states of every kind the chain reads: the type and URL l0proof decodes are Accumulate's
	for i := 0; i < 2000; i++ {
		acct := randomAccount(r, i)
		main, err := acct.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p := l0proof.AccountProof{MainState: main, SecondaryState: make([]byte, 32), Chains: []l0proof.Bytes{make([]byte, 32)}, Pending: make([]byte, 32)}
		st, err := p.State(nil)
		if err != nil || st.Type != acct.Type().GetEnumValue() || st.URL != acct.GetUrl().String() {
			t.Fatalf("account %d (%v): l0proof %+v %v", i, acct.Type(), st, err)
		}
		count(true)
	}

	if cases < 10000 {
		t.Fatalf("only %d cases ran; DF-01 requires 10,000", cases)
	}
	t.Logf("%d randomised cases agree with Accumulate (%d valid, %d invalid)", cases, valid, invalid)
}

func randomWriteData(r *rand.Rand) (*protocol.Transaction, *protocol.WriteData) {
	var items [][]byte
	for k := 1 + r.Intn(5); k > 0; k-- {
		d := make([]byte, r.Intn(120))
		r.Read(d)
		items = append(items, d)
	}
	wd := &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: items}, WriteToState: r.Intn(2) == 0}
	txn := new(protocol.Transaction)
	txn.Header.Principal = url.MustParse(fmt.Sprintf("acc://df01-%d.acme/data-%d", r.Intn(1e6), r.Intn(100)))
	copy(txn.Header.Initiator[:], rnd32(r))
	if r.Intn(2) == 0 {
		txn.Header.Memo = fmt.Sprintf("memo %d", r.Int())
	}
	if r.Intn(3) == 0 {
		txn.Header.Metadata = rnd32(r)
	}
	txn.Body = wd
	return txn, wd
}

func randomAccount(r *rand.Rand, i int) protocol.Account {
	u := url.MustParse(fmt.Sprintf("acc://df01-acct-%d.acme/a%d", i, r.Intn(1000)))
	switch i % 7 {
	case 0:
		return &protocol.DataAccount{Url: u}
	case 1:
		lda, _ := protocol.LiteDataAddress(rnd32(r))
		return &protocol.LiteDataAccount{Url: lda}
	case 2:
		kp := &protocol.KeyPage{Url: u, AcceptThreshold: uint64(1 + r.Intn(3)), Version: uint64(r.Intn(9))}
		kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: rnd32(r)})
		return kp
	case 3:
		return &protocol.ADI{Url: u}
	case 4:
		return &protocol.SystemLedger{Url: u, Index: uint64(r.Intn(1e6))}
	case 5:
		return &protocol.AnchorLedger{Url: u}
	default:
		return &protocol.KeyBook{Url: u, PageCount: uint64(1 + r.Intn(4))}
	}
}

// DF-01 on the captured fixtures: Accumulate re-derives every link of both committed chains (the transaction hash from its own decoding of the header and
// body, each path as a merkle.Receipt, the Directory ledger's BPT value from its own merkle hasher and account decoding).
func TestDF01_AgreesWithAccumulateOnTheCapturedFixtures(t *testing.T) {
	for _, name := range []string{"kermit", "simulator"} {
		raw, err := os.ReadFile(filepath.Join("..", "l0proof", "testdata", name, "chain.json"))
		if err != nil {
			t.Fatal(err)
		}
		var c l0proof.L0ProofChain
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		txn := new(protocol.Transaction)
		if err := txn.Header.UnmarshalBinary(c.Transaction.Header); err != nil {
			t.Fatal(err)
		}
		body, err := protocol.UnmarshalTransactionBody(c.Transaction.Body)
		if err != nil {
			t.Fatal(err)
		}
		wd := body.(*protocol.WriteData)
		entry := &protocol.DoubleHashDataEntry{}
		for _, d := range c.Transaction.Entry {
			entry.Data = append(entry.Data, d)
		}
		wd.Entry = entry
		txn.Body = wd
		mine, _, err := c.Transaction.Hash(nil)
		if err != nil || !bytes.Equal(mine, txn.GetHash()) {
			t.Fatalf("%s: transaction hash %X vs Accumulate %X (%v)", name, mine, txn.GetHash(), err)
		}

		start := txn.GetHash()
		for _, seg := range []l0proof.Path{c.EntryPath, c.Directory.AnchorPath} {
			rc := &merkle.Receipt{Start: start, Entries: toMerkle(seg)}
			got, err := seg.Apply(start, 4096)
			if err != nil {
				t.Fatal(err)
			}
			rc.Anchor = got
			if !rc.Validate(nil) {
				t.Fatalf("%s: Accumulate does not validate a fixture path", name)
			}
			start = got
		}
		led := c.Directory.Ledger
		acct, err := protocol.UnmarshalAccount(led.MainState)
		if err != nil {
			t.Fatal(err)
		}
		st, err := led.State(nil)
		if err != nil || st.URL != acct.GetUrl().String() || st.Type != acct.Type().GetEnumValue() {
			t.Fatalf("%s: ledger decode %+v vs %v %v (%v)", name, st, acct.GetUrl(), acct.Type(), err)
		}
		var chains merkle.Hasher
		for _, a := range led.Chains {
			chains = append(chains, a)
		}
		sum := sha256.Sum256(led.MainState)
		value := merkle.Hasher{sum[:], led.SecondaryState, chains.MerkleHash(), led.Pending}.MerkleHash()
		rc := &merkle.Receipt{Start: value, Entries: toMerkle(led.StatePath), Anchor: st.Root}
		if !rc.Validate(nil) {
			t.Fatalf("%s: Accumulate does not reach the ledger's BPT root", name)
		}
		if !bytes.Equal(led.Chains[led.Chain], start) {
			t.Fatalf("%s: the root anchor is not the ledger chain", name)
		}
	}
}

func toMerkle(p l0proof.Path) []*merkle.ReceiptEntry {
	out := make([]*merkle.ReceiptEntry, len(p))
	for i, s := range p {
		out[i] = &merkle.ReceiptEntry{Right: s.Right, Hash: s.Hash}
	}
	return out
}

// DF-01 bite: the comparison is against Accumulate's STRICT validation. A receipt with a 33-byte entry is valid under Relaxed validation, invalid
// strictly, and refused by l0proof.
func TestDF01_TheComparisonIsAgainstStrictValidation(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	list := [][]byte{rnd32(r), rnd32(r), rnd32(r)}
	rc := merkle.Hasher(list).Receipt(0, 2)
	rc.Entries[0].Hash = append(rc.Entries[0].Hash, 0xAA)
	rc.Anchor = rc.Start
	for _, e := range rc.Entries {
		if e.Right {
			rc.Anchor = combine(rc.Anchor, e.Hash)
		} else {
			rc.Anchor = combine(e.Hash, rc.Anchor)
		}
	}
	if !rc.Validate(&merkle.ValidateOptions{Relaxed: true}) || rc.Validate(nil) {
		t.Fatal("premise: relaxed accepts and strict refuses a 33-byte entry")
	}
	if agree(t, "33-byte entry", rc) {
		t.Fatal("strict validation accepted it")
	}
}

func combine(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}
