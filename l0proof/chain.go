// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package l0proof is Infrix's own verifier of an Accumulate anchor: that a 32-byte value (a bundle's batch root) was written to Accumulate by a WriteData
// to a named data account, and that the Directory's consensus certified it. It depends on the standard library and crypto only; Accumulate's and CometBFT's
// own implementations are used solely by the test-only differential suites, which hold every rule here to theirs.
//
// The proof is a chain of links, each computed by the verifier from the content of the one below it, and the last held to a Directory header certified
// from the verifier's PIN:
//
//	value        -- is a data item of ------> a WriteData to the anchor account     tx hash recomputed (protocol/transaction_hash.go)
//	tx hash      -- EntryPath --------------> its partition's root-chain anchor     the account's main chain, then the partition root chain
//	                                                                                (internal/database/indexing/receipts.go ReceiptForChainEntry)
//	root anchor  -- Directory.AnchorPath ---> the Directory root-chain anchor       the partition anchored that root on the Directory (an element of
//	                                                                                acc://dn.acme/anchors' anchor(<partition>)-root chain), then the
//	                                                                                Directory root chain (ReceiptForChainIndex with a target height)
//	Directory    -- Directory.Ledger -------> the Directory BPT root                the root chain is a chain of the Directory ledger (acc://dn.acme/ledger),
//	root anchor                                                                     whose BPT value is recomputed from its state (internal/database/
//	                                                                                observer_prod.go hashState) and its BPT receipt applied
//	                                                                                (pkg/database/bpt/bpt_receipt.go)
//	Directory BPT root == the AppHash of a Directory header (Accumulate docs/apphash.md: the AppHash is exactly the BPT root), certified by
//	                      consensus.VerifyTrace from the pin.
//
// The anchor account is bound by the transaction itself: its header names the principal, the verifier recomputes the hash from the header, and Accumulate
// records a transaction hash on its principal's main chain only when the transaction executes (internal/core/execute/v2/block). An account on the
// Directory takes the same route through the Directory's own anchor of its root chain (anchor(directory)-root).
package l0proof

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/l0proof/internal/hexb"
)

// Bytes is a byte string, hex in JSON.
type Bytes = hexb.Bytes

// DirectoryLedgerURL is the Directory's system ledger (protocol.DnUrl().JoinPath(protocol.Ledger)), whose chains include the Directory root chain.
const DirectoryLedgerURL = "acc://dn.acme/ledger"

// L0ProofChain is a complete, offline-verifiable proof that a value was anchored on Accumulate and certified by the Directory.
type L0ProofChain struct {
	// Incarnation is the ID of the pin the chain was captured under. It is a LABEL: the verifier compares it with its own pin and refuses a mismatch;
	// it never selects a pin.
	Incarnation string `json:"incarnation"`
	// Transaction is the WriteData that carried the value.
	Transaction WriteDataTx `json:"transaction"`
	// EntryPath proves the transaction hash reaches its partition's root-chain anchor, through the anchor account's main chain.
	EntryPath Path `json:"entryPath"`
	// Directory carries that root-chain anchor to the Directory BPT root.
	Directory DirectoryHop `json:"directory"`
	// Consensus is the trace of Directory light blocks from the pin; the last certifies the Directory root as its AppHash.
	Consensus []consensus.LightBlock `json:"consensus"`
}

// WriteDataTx is the transaction that carried the value, in the exact Accumulate binary the network hashed.
type WriteDataTx struct {
	Header Bytes   `json:"header"` // TransactionHeader.MarshalBinary
	Body   Bytes   `json:"body"`   // the WriteData with its Entry removed, MarshalBinary (WriteData.GetHash hashes it this way)
	Entry  []Bytes `json:"entry"`  // the data items of the DoubleHashDataEntry
}

// AccountProof proves an account's state, including the anchor of each of its chains, is committed in a partition's BPT root. It is the BPT building
// block: the chain verifier uses it for the Directory ledger's root chain, and a key-page proof uses it for the page's main state.
type AccountProof struct {
	MainState      Bytes   `json:"mainState"`      // the account's main state, MarshalBinary
	SecondaryState Bytes   `json:"secondaryState"` // the merkle hash of the account's secondary state (directory, events)
	Chains         []Bytes `json:"chains"`         // the anchor of every chain of the account, in the account's chain order
	Chain          int     `json:"chain"`          // which of Chains the link below reaches
	Pending        Bytes   `json:"pending"`        // the merkle hash of the account's pending transactions
	StatePath      Path    `json:"statePath"`      // the BPT receipt from the account's BPT value to the partition's BPT root
}

// DirectoryHop carries a partition's root-chain anchor into the Directory's BPT root.
type DirectoryHop struct {
	AnchorPath Path         `json:"anchorPath"` // from the partition's root anchor, as anchored on the Directory, to the Directory root-chain anchor
	Ledger     AccountProof `json:"ledger"`     // the Directory ledger, whose chains include that root chain
}

// Expectation is what the RELYING PARTY expects the chain to prove; none of it is read from the proof.
type Expectation struct {
	AnchorAccount string // the data account the value must have been written to
	Leaf          []byte // the value that must be, byte for byte, one of the WriteData's data items (for a bundle: its 32-byte batch root)
}

// Options select the trust root. With no override the pin is the one compiled in for Network; an override is used only when the relying party passes one
// explicitly, and the result says so.
type Options struct {
	Network     string         // the network whose compiled pin to use, e.g. "kermit"
	OverridePin *consensus.Pin // an explicit relying-party pin; never taken from a proof
	Limits      *Limits        // nil means DefaultLimits
}

// Result is the verdict. Verified is true only when every link was checked; otherwise Reason names the first link that failed, and nothing is credited.
type Result struct {
	Verified        bool
	Reason          string
	Network         string // the pin's network
	Pin             string // the pin's ID: the incarnation this verdict is relative to
	PinOverridden   bool   // the relying party supplied the pin explicitly
	TxHash          Bytes  // the recomputed transaction hash
	DirectoryRoot   Bytes  // the Directory BPT root the chain reached
	DirectoryHeight int64  // the height of the certified Directory header
}

func fail(r Result, format string, args ...any) Result {
	r.Verified = false
	r.Reason = fmt.Sprintf(format, args...)
	r.TxHash, r.DirectoryRoot, r.DirectoryHeight = nil, nil, 0
	return r
}

// Verify checks every link of the chain against the expectation and the verifier's pin. It never panics and never credits a partial chain.
func Verify(c *L0ProofChain, exp Expectation, opts Options) Result {
	lim := DefaultLimits
	if opts.Limits != nil {
		lim = *opts.Limits
	}
	var res Result
	pin, overridden, err := selectPin(opts)
	if err != nil {
		return fail(res, "%v", err)
	}
	res.Network, res.Pin, res.PinOverridden = pin.Network, pin.ID(), overridden
	if c == nil {
		return fail(res, "no L0 proof chain")
	}
	if c.Incarnation != res.Pin {
		return fail(res, "the chain was captured under incarnation %q, not the verifier's pin %q (%s)", c.Incarnation, res.Pin, pin.Network)
	}
	if len(exp.Leaf) == 0 || len(exp.Leaf) > lim.MaxTransactionBytes {
		return fail(res, "the expected value is %d bytes; between 1 and %d are allowed", len(exp.Leaf), lim.MaxTransactionBytes)
	}
	if exp.AnchorAccount == "" {
		return fail(res, "no expected anchor account")
	}

	// the value is a data item of the transaction, which went to the anchor account
	txHash, principal, err := c.Transaction.Hash(&lim)
	if err != nil {
		return fail(res, "transaction: %v", err)
	}
	if !sameURL(principal, exp.AnchorAccount) {
		return fail(res, "the transaction wrote to %s, not the anchor account %s", principal, exp.AnchorAccount)
	}
	found := false
	for _, item := range c.Transaction.Entry {
		if bytes.Equal(item, exp.Leaf) {
			found = true
			break
		}
	}
	if !found {
		return fail(res, "the transaction's entry does not carry the expected value %X", exp.Leaf)
	}

	// the transaction reaches its partition's root anchor, which the Directory anchored, through the Directory root chain to the Directory ledger's state
	partitionRoot, err := c.EntryPath.Apply(txHash, lim.MaxPathSteps)
	if err != nil {
		return fail(res, "entry path: %v", err)
	}
	rootAnchor, err := c.Directory.AnchorPath.Apply(partitionRoot, lim.MaxPathSteps)
	if err != nil {
		return fail(res, "directory anchor path: %v", err)
	}
	st, err := c.Directory.Ledger.State(&lim)
	if err != nil {
		return fail(res, "directory ledger: %v", err)
	}
	if !bytes.Equal(c.Directory.Ledger.Chains[c.Directory.Ledger.Chain], rootAnchor) {
		return fail(res, "the Directory root anchor %X is not the Directory ledger's chain %d anchor", rootAnchor, c.Directory.Ledger.Chain)
	}
	if !sameURL(st.URL, DirectoryLedgerURL) {
		return fail(res, "the directory hop ends in %s, not the Directory ledger %s", st.URL, DirectoryLedgerURL)
	}
	if st.Type != accountTypeSystemLedger {
		return fail(res, "the Directory ledger is type %d, not a system ledger", st.Type)
	}
	root := st.Root

	// the Directory root is the AppHash of a header the pinned Directory validators certified
	last, err := consensus.VerifyTrace(pin, c.Consensus, lim.Consensus)
	if err != nil {
		return fail(res, "consensus: %v", err)
	}
	if !bytes.Equal(last.Header.AppHash, root) {
		return fail(res, "the Directory root %X is not the AppHash %X of the certified header at height %d", root, []byte(last.Header.AppHash), last.Header.Height)
	}
	res.Verified = true
	res.TxHash, res.DirectoryRoot, res.DirectoryHeight = txHash, root, last.Header.Height
	return res
}

// Hash recomputes the transaction hash and reads its principal (protocol/transaction_hash.go calcHash and hashWriteData, protocol/data_entry.go DoubleHashDataEntry.Hash):
//
//	entry hash = SHA-256( MerkleRoot( SHA-256(item) for each item ) )
//	body hash  = MerkleRoot( SHA-256(body without entry), entry hash )
//	tx hash    = SHA-256( SHA-256(header) ‖ body hash )
func (t *WriteDataTx) Hash(lim *Limits) ([]byte, string, error) {
	if lim == nil {
		lim = &DefaultLimits
	}
	if len(t.Header)+len(t.Body) > lim.MaxTransactionBytes {
		return nil, "", fmt.Errorf("the header and body are %d bytes, over the limit of %d", len(t.Header)+len(t.Body), lim.MaxTransactionBytes)
	}
	principal, err := decodeTxPrincipal(t.Header)
	if err != nil {
		return nil, "", err
	}
	if err := checkWriteDataBody(t.Body); err != nil {
		return nil, "", err
	}
	if len(t.Entry) == 0 {
		return nil, "", errors.New("the entry has no data")
	}
	if len(t.Entry) > lim.MaxEntryItems {
		return nil, "", fmt.Errorf("the entry has %d items, over the limit of %d", len(t.Entry), lim.MaxEntryItems)
	}
	size := 0
	items := make([][]byte, len(t.Entry))
	for i, d := range t.Entry {
		size += len(d)
		items[i] = sha(d)
	}
	if size > lim.MaxTransactionBytes {
		return nil, "", fmt.Errorf("the entry is %d bytes, over the limit of %d", size, lim.MaxTransactionBytes)
	}
	entryHash := sha(MerkleRoot(items))
	bodyHash := MerkleRoot([][]byte{sha(t.Body), entryHash})
	return combine(sha(t.Header), bodyHash), principal, nil
}

// AccountState is what an AccountProof establishes.
type AccountState struct {
	Root []byte // the partition BPT root the account's state is committed in
	Type uint64 // the account type, read from its main state
	URL  string // the account URL, read from its main state
}

// State recomputes the account's BPT value from its state (observedAccount.hashState: main state, secondary state, chains, pending), applies the BPT
// receipt, and returns the partition BPT root with the account's type and URL read from its main state.
func (a *AccountProof) State(lim *Limits) (*AccountState, error) {
	if lim == nil {
		lim = &DefaultLimits
	}
	if len(a.MainState) > lim.MaxMainStateBytes {
		return nil, fmt.Errorf("the main state is %d bytes, over the limit of %d", len(a.MainState), lim.MaxMainStateBytes)
	}
	typ, url, err := decodeAccountHeader(a.MainState)
	if err != nil {
		return nil, err
	}
	if len(a.SecondaryState) != HashSize || len(a.Pending) != HashSize {
		return nil, errors.New("the secondary-state and pending hashes must be 32 bytes")
	}
	if len(a.Chains) == 0 || len(a.Chains) > lim.MaxChains {
		return nil, fmt.Errorf("the account lists %d chains; between 1 and %d are allowed", len(a.Chains), lim.MaxChains)
	}
	chains := make([][]byte, len(a.Chains))
	for i, c := range a.Chains {
		if len(c) != HashSize {
			return nil, fmt.Errorf("chain %d's anchor is %d bytes, want 32", i, len(c))
		}
		chains[i] = c
	}
	if a.Chain < 0 || a.Chain >= len(a.Chains) {
		return nil, fmt.Errorf("chain index %d is outside the account's %d chains", a.Chain, len(a.Chains))
	}
	value := MerkleRoot([][]byte{sha(a.MainState), a.SecondaryState, MerkleRoot(chains), a.Pending})
	root, err := a.StatePath.Apply(value, lim.MaxPathSteps)
	if err != nil {
		return nil, fmt.Errorf("state path: %w", err)
	}
	return &AccountState{Root: root, Type: typ, URL: url}, nil
}

// sameURL compares Accumulate URLs as the protocol does: case-insensitively (url.URL.Equal).
func sameURL(a, b string) bool { return strings.EqualFold(a, b) }
