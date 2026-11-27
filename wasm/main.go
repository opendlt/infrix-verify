// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//go:build js && wasm

// Command wasm is the Go verifier compiled to WebAssembly for @infrix/client (native proof plan phase 8): it registers infrixVerify(packageJSON,
// optionsJSON) on the global object, which returns verifykit.VerifyJSON's report JSON, or throws its error. It is the same body as the native verifier.
//
//	GOOS=js GOARCH=wasm go build -o infrix-verify.wasm ./wasm
package main

import (
	"syscall/js"

	"github.com/opendlt/infrix-verify/verifykit"
)

func main() {
	js.Global().Set("infrixVerify", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.Global().Get("Error").New("infrixVerify(packageJSON, optionsJSON)")
		}
		opts := ""
		if len(args) > 1 && args[1].Type() == js.TypeString {
			opts = args[1].String()
		}
		out, err := verifykit.VerifyJSON([]byte(args[0].String()), []byte(opts))
		if err != nil {
			return js.Global().Get("Error").New(err.Error())
		}
		return string(out)
	}))
	select {}
}
