// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifykit

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/opendlt/infrix-schema/evidence"
)

// wasmCase is one corpus entry: a package and the offline options.
type wasmCase struct {
	Name string          `json:"name"`
	Pkg  json.RawMessage `json:"pkg"`
	Opts json.RawMessage `json:"opts"`
}

// wasmCorpus is the Accumulate-proven bundle in every shape the levels distinguish (L4/G2, L3/G1, G0 without key pages, the Kermit pin refusing a
// simulator chain, a tampered chain) and the legacy anchored bundle.
func wasmCorpus(t *testing.T) []wasmCase {
	p := loadAccProofs(t)
	pin, _ := json.Marshal(JSONOptions{L0Pin: &p.Pin, GovernanceAccount: accAccount, GovernancePage: accPage})
	kermit, _ := json.Marshal(JSONOptions{GovernanceAccount: accAccount, GovernancePage: accPage, Require: "L4/G2"})
	enc := func(pkg *evidence.PortableEvidencePackage) json.RawMessage {
		b, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return []wasmCase{
		{"l4g2", enc(accPackage(t, nil)), pin},
		{"l3g1", enc(accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) { b.L0Proof, b.GovernanceExecution = nil, nil })), pin},
		{"g0-no-key-pages", enc(accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) { b.KeyPageProofs = nil })), pin},
		{"kermit-pin", enc(accPackage(t, nil)), kermit},
		{"tampered-chain", enc(accPackage(t, func(b *evidence.EvidenceBundle, _ *accProofs) {
			b.L0Proof = bytes.Replace(b.L0Proof, []byte(`pin:`), []byte(`pin:0`), 1)
		})), pin},
		{"legacy-anchored", enc(buildPortable(t, true)), json.RawMessage(`{}`)},
	}
}

// DF-03 (and the body of DF-04): the WASM build of the verifier returns BYTE-IDENTICAL reports to the native Go verifier on the whole corpus. The WASM is
// built from ./wasm here and run under Node with Go's own wasm_exec.js, exactly as @infrix/client loads it.
func TestDF03_TheWASMVerifierMatchesTheNativeVerifierByteForByte(t *testing.T) {
	dir := t.TempDir()
	wasm := filepath.Join(dir, "infrix-verify.wasm")
	build := exec.Command("go", "build", "-o", wasm, "./wasm")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the WASM verifier: %v\n%s", err, out)
	}
	corpus := wasmCorpus(t)
	cases, _ := json.Marshal(corpus)
	casesPath := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(casesPath, cases, 0o644); err != nil {
		t.Fatal(err)
	}
	execJS := filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec.js")
	driver := `
require(process.argv[2]);
const fs = require("fs");
const go = new Go();
WebAssembly.instantiate(fs.readFileSync(process.argv[3]), go.importObject).then((r) => {
  go.run(r.instance);
  const cases = JSON.parse(fs.readFileSync(process.argv[4], "utf8"));
  const out = cases.map((c) => {
    const v = globalThis.infrixVerify(JSON.stringify(c.pkg), JSON.stringify(c.opts));
    if (v instanceof Error) { throw v; }
    return v;
  });
  fs.writeFileSync(process.argv[5], JSON.stringify(out));
  process.exit(0);
});`
	driverPath := filepath.Join(dir, "driver.js")
	if err := os.WriteFile(driverPath, []byte(driver), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.json")
	run := exec.Command("node", driverPath, execJS, wasm, casesPath, outPath)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run the WASM verifier under node: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil || len(got) != len(corpus) {
		t.Fatalf("the WASM verifier returned %d reports for %d cases: %v", len(got), len(corpus), err)
	}
	levels := map[string]string{}
	for i, c := range corpus {
		pkgJSON, _ := json.Marshal(c.Pkg)
		optsJSON, _ := json.Marshal(c.Opts)
		native, err := VerifyJSON(pkgJSON, optsJSON)
		if err != nil {
			t.Fatalf("%s: native: %v", c.Name, err)
		}
		if got[i] != string(native) {
			t.Fatalf("%s: the WASM report differs from the native report\nwasm:   %s\nnative: %s", c.Name, got[i], native)
		}
		var r Report
		_ = json.Unmarshal(native, &r)
		levels[c.Name] = r.Tier
	}
	// the corpus spans the levels it claims to, so agreement is not agreement on one verdict
	for name, want := range map[string]string{"l4g2": "L4/G2", "l3g1": "L3/G1", "g0-no-key-pages": "L4/G0", "kermit-pin": "L3/G0"} {
		if levels[name] != want {
			t.Fatalf("corpus case %s is %s, want %s (all: %v)", name, levels[name], want, levels)
		}
	}
	if !strings.HasPrefix(levels["tampered-chain"], "L3/") {
		t.Fatalf("the tampered chain reached %s", levels["tampered-chain"])
	}
}
