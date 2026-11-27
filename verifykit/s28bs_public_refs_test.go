// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var (
	reHex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePinID      = regexp.MustCompile(`^pin:[0-9a-f]{64}$`)
	reLongHexRun = regexp.MustCompile(`[0-9a-f]{48,}`)
)

// Brief 28bs row 1 (main's ruling on the agent key scan): the embedded-proof checks carry their full public identifiers under labelled keys,
// each in its exact format (txHash, batchRoot and directoryRoot as 64 lowercase hex; pinId as "pin:" then 64 lowercase hex), and the prose
// names each by an identifying prefix only, so no check detail carries an unlabelled 32-byte hex run.
func TestS28bsTheEmbeddedProofChecksLabelTheirPublicIdentifiersInTheirExactFormats(t *testing.T) {
	o := accOpts(t)
	r := Verify(context.Background(), accPackage(t, nil), o)
	if !r.Verified || r.ProofLevel != "L4" || r.GovernanceLevel != "G2" {
		t.Fatalf("control: %s/%s verified=%v", r.ProofLevel, r.GovernanceLevel, r.Verified)
	}
	want := map[string]bool{"embedded_l0_proof": false, "governance_execution": false}
	for _, c := range r.Checks {
		if reLongHexRun.MatchString(c.Detail) {
			t.Errorf("%s: the detail carries an unlabelled long hex run: %s", c.Name, c.Detail)
		}
		if _, ok := want[c.Name]; !ok || c.Status != CheckPass {
			continue
		}
		want[c.Name] = true
		p := c.Public
		if p == nil || !reHex64.MatchString(p.TxHash) || !rePinID.MatchString(p.PinID) || p.PinID != o.L0Pin.ID() {
			t.Fatalf("%s: the public identifiers are not in their exact formats: %+v", c.Name, p)
		}
		if !strings.Contains(c.Detail, p.TxHash[:16]+"...") || !strings.Contains(c.Detail, shortPinID(p.PinID)) {
			t.Fatalf("%s: the prose does not name the identifiers by their prefixes: %s", c.Name, c.Detail)
		}
		if c.Name == "embedded_l0_proof" && (!reHex64.MatchString(p.BatchRoot) || !reHex64.MatchString(p.DirectoryRoot)) {
			t.Fatalf("embedded_l0_proof: the roots are not 64 lowercase hex: %+v", p)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("%s did not pass", name)
		}
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"public":{"txHash":"`) {
		t.Fatalf("the rendered report carries no labelled identifiers:\n%s", out)
	}
}

// The one pin parser every client runs (brief 28bs row 2): a local run's pin round-trips and applies its trust root; a pin for another
// network, an unknown field, trailing data, a pin with no validators and a pin with no governance page are each refused.
func TestS28bsTheLocalEmbeddedPinParserRefusesEveryMalformedPin(t *testing.T) {
	p := loadAccProofs(t).Pin
	p.Network = LocalEmbeddedNetwork
	good := LocalEmbeddedPin{Pin: p, GovernanceAccount: accAccount, GovernancePage: accPage}
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLocalEmbeddedPin(data)
	if err != nil {
		t.Fatalf("a good pin was refused: %v", err)
	}
	var o Options
	got.Apply(&o)
	if o.L0Pin == nil || o.L0Pin.ID() != p.ID() || o.GovernanceAccount != accAccount || o.GovernancePage != accPage {
		t.Fatalf("Apply did not set the trust root: %+v", o)
	}
	mutate := func(f func(*LocalEmbeddedPin)) []byte {
		c := good
		f(&c)
		b, _ := json.Marshal(c)
		return b
	}
	for name, bad := range map[string][]byte{
		"another network":    mutate(func(c *LocalEmbeddedPin) { c.Pin.Network = "kermit" }),
		"no validators":      mutate(func(c *LocalEmbeddedPin) { c.Pin.Validators.Validators = nil }),
		"no governance page": mutate(func(c *LocalEmbeddedPin) { c.GovernancePage = "" }),
		"an unknown field":   []byte(strings.Replace(string(data), "{", `{"extra":1,`, 1)),
		"trailing data":      []byte(fmt.Sprintf("%s {}", data)),
	} {
		if _, err := ParseLocalEmbeddedPin(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
