// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Command capture-kermit captures the complete L0 proof chain of an Infrix WriteData already executed on Kermit (NEVER mainnet) as an Infrix-owned
// fixture: it reads the transaction, its main-chain receipt and the account's state receipt (BVN), waits for the BVN's BPT root to reach the Directory's
// anchor ledger, reads the Directory receipts and ledger state, and fetches the Directory header and commit from Kermit's Directory CometBFT RPC. Every link
// is checked with Accumulate's and CometBFT's own code here, and the result is verified with l0proof against the compiled Kermit pin before it is written.
//
// The default transaction is Infrix's governed L0 write of 2026-09-03 (docs/release/artifacts/accumulate-testnet-governed-l0-write.json in core), on the
// data account acc://infrixdevnet-1782843230226786400-1.acme/data. The leaf it proves is the transaction's first data item.
//
//	go run ./cmd/capture-kermit -out ../l0proof/testdata/kermit
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	cmthttp "github.com/cometbft/cometbft/rpc/client/http"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/opendlt/infrix-verify/l0proof"
	"github.com/opendlt/infrix-verify/l0proof/consensus"
	"github.com/opendlt/infrix-verify/l0proofref/capture"
	"gitlab.com/accumulatenetwork/accumulate/exp/apiutil"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	errors2 "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func main() {
	apiURL := flag.String("api", "https://kermit.accumulatenetwork.io/v3", "Kermit's Accumulate v3 API")
	cmtURL := flag.String("cometbft", "http://kermit.accumulatenetwork.io:16592", "Kermit's Directory CometBFT RPC")
	out := flag.String("out", "", "directory to write the fixture to")
	txidFlag := flag.String("txid", "acc://12e0a1473967de9ee596c15e53f36ecb6f98936fe5016dd4788aab38d4bdea1d@infrixdevnet-1782843230226786400-1.acme/data", "the executed WriteData to capture")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	for _, u := range []string{*apiURL, *cmtURL} {
		if !strings.Contains(u, "kermit") {
			log.Fatalf("refusing %s: the capture runs against Kermit only, never mainnet", u)
		}
	}
	ctx := context.Background()
	c := jsonrpc.NewClient(*apiURL)
	q := api.Querier2{Querier: c}
	txid, err := url.ParseTxID(*txidFlag)
	check(err)
	rec, err := q.QueryTransaction(ctx, txid, nil)
	check(err)
	if rec.Status != errors2.Delivered {
		log.Fatalf("transaction %v has status %v, not delivered", txid, rec.Status)
	}
	wd, ok := rec.Message.Transaction.Body.(*protocol.WriteData)
	if !ok || wd.Entry == nil || len(wd.Entry.GetData()) == 0 {
		log.Fatalf("transaction %v is not a WriteData with data", txid)
	}
	leaf := wd.Entry.GetData()[0]
	dataURL := rec.Message.Transaction.Header.Principal

	partition := route(ctx, c, dataURL)
	log.Printf("anchor account %v is on %s", dataURL, partition)

	a, partRoot, err := capture.TxEntry(ctx, q, txid)
	check(err)
	hop, dnBlock, dnRoot, err := capture.DirectoryHop(ctx, q, partition, partRoot, capture.Options{Poll: time.Second, Attempts: 60})
	check(err)
	a.Chain.Directory = *hop
	log.Printf("Directory block %d root %X", dnBlock, dnRoot)

	cmt, err := cmthttp.New(*cmtURL, "/websocket")
	check(err)
	pin, err := l0proof.CompiledPin(l0proof.NetworkKermit)
	check(err)
	target := int64(dnBlock) + 1
	var lb consensus.LightBlock
	waitFor("the certifying Directory header", func() bool {
		cr, err := cmt.Commit(ctx, &target)
		if err != nil {
			return false
		}
		perPage := 100
		page := 1
		vals, err := cmt.Validators(ctx, &target, &page, &perPage)
		if err != nil {
			return false
		}
		next := target + 1
		nvals, err := cmt.Validators(ctx, &next, &page, &perPage)
		if err != nil {
			return false
		}
		lb = capture.LightBlock(&cr.SignedHeader, mustSet(vals.Validators), mustSet(nvals.Validators))
		return true
	})
	if string(lb.Header.AppHash) != string(dnRoot[:]) {
		log.Fatalf("the header at %d carries AppHash %X, not the captured Directory root %X", target, []byte(lb.Header.AppHash), dnRoot)
	}
	a.Chain.Consensus = []consensus.LightBlock{lb}
	a.Chain.Incarnation = pin.ID()

	exp := l0proof.Expectation{AnchorAccount: dataURL.String(), Leaf: leaf}
	res := l0proof.Verify(&a.Chain, exp, l0proof.Options{Network: l0proof.NetworkKermit})
	if !res.Verified {
		log.Fatalf("the captured chain does not verify against the compiled Kermit pin: %s", res.Reason)
	}
	check(os.MkdirAll(*out, 0o755))
	write(filepath.Join(*out, "chain.json"), &a.Chain)
	write(filepath.Join(*out, "expect.json"), map[string]any{"anchorAccount": exp.AnchorAccount, "leaf": l0proof.Bytes(exp.Leaf)})
	write(filepath.Join(*out, "capture.json"), map[string]any{
		"capturedAt": time.Now().UTC().Format(time.RFC3339), "api": *apiURL, "cometbft": *cmtURL, "txid": txid.String(), "partition": partition,
		"directoryBlock": dnBlock, "headerHeight": target, "pin": pin.ID(), "command": "go run ./cmd/capture-kermit -out ../l0proof/testdata/kermit -txid " + txid.String(),
	})
	log.Printf("verified at Directory height %d under %s; wrote %s", res.DirectoryHeight, res.Pin, *out)
}

func mustSet(vs []*cmttypes.Validator) *cmttypes.ValidatorSet { return cmttypes.NewValidatorSet(vs) }

func route(ctx context.Context, c *jsonrpc.Client, u *url.URL) string {
	ns, err := c.NetworkStatus(ctx, api.NetworkStatusOptions{Partition: protocol.Directory})
	check(err)
	p, err := apiutil.RouteAccount(ns.Routing, u)
	check(err)
	return p
}

func waitFor(what string, ok func() bool) {
	for i := 0; i < 120; i++ {
		if ok() {
			return
		}
		time.Sleep(time.Second)
	}
	log.Fatal(errors.New("timed out waiting for " + what))
}

func write(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	check(err)
	check(os.WriteFile(path, append(b, '\n'), 0o644))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
