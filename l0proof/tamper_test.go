// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package l0proof_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/opendlt/infrix-verify/l0proof"
)

// TS-ALL for the L0 proof chain: a generator walks EVERY field of an L0ProofChain (the transaction, the entry path, the account proof, the Directory hop
// and its ledger proof, every light block's header, commit, signatures and validator sets) and, for each, flips a bit, truncates, extends, reorders, swaps
// with a sibling and zeroes. Every mutation that changes the chain must make it fail, and the failure names the field. A reflection census then requires
// every field path of the TYPE to have had at least one effective mutation, so a field added later without a mutation turns this test red.

// mutation is one change to one field: apply makes it, undo reverts it.
type mutation struct {
	path, kind string
	apply      func()
	undo       func()
}

// typePath is a field path with slice indices erased ("Consensus[].Header.AppHash"), which is what the census compares.
func typePath(p string) string {
	var b strings.Builder
	skip := false
	for _, r := range p {
		switch {
		case r == '[':
			skip = true
			b.WriteString("[]")
		case r == ']':
			skip = false
		case !skip:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// mutations enumerates the mutations of every field reachable from v.
func mutations(v reflect.Value, path string, out *[]mutation) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		orig := v.Elem()
		*out = append(*out, mutation{path: path, kind: "zero", apply: func() { v.Set(reflect.Zero(v.Type())) }, undo: func() { v.Set(orig.Addr()) }})
		mutations(v.Elem(), path, out)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			mutations(v.Field(i), join(path, v.Type().Field(i).Name), out)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			bytesMutations(v, path, out)
			return
		}
		sliceMutations(v, path, out)
		for i := 0; i < v.Len(); i++ {
			mutations(v.Index(i), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.String:
		s := v.String()
		set := func(x string) func() { return func() { v.SetString(x) } }
		undo := set(s)
		if s != "" {
			*out = append(*out,
				mutation{path, "flip", set(string(s[0]^1) + s[1:]), undo},
				mutation{path, "truncate", set(s[:len(s)-1]), undo},
				mutation{path, "zero", set(""), undo})
		}
		*out = append(*out, mutation{path, "extend", set(s + "x"), undo})
	case reflect.Bool:
		b := v.Bool()
		*out = append(*out, mutation{path, "flip", func() { v.SetBool(!b) }, func() { v.SetBool(b) }})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		undo := func() { v.SetInt(n) }
		*out = append(*out, mutation{path, "flip", func() { v.SetInt(n ^ 1) }, undo}, mutation{path, "zero", func() { v.SetInt(0) }, undo},
			mutation{path, "extend", func() { v.SetInt(n + 1<<20) }, undo})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		undo := func() { v.SetUint(n) }
		*out = append(*out, mutation{path, "flip", func() { v.SetUint(n ^ 1) }, undo}, mutation{path, "zero", func() { v.SetUint(0) }, undo})
	default:
		panic(fmt.Sprintf("the tamper generator has no mutation for %s (%s): add one", path, v.Kind()))
	}
}

func bytesMutations(v reflect.Value, path string, out *[]mutation) {
	orig := append([]byte(nil), v.Bytes()...)
	set := func(b []byte) func() { return func() { v.SetBytes(b) } }
	undo := func() { v.SetBytes(append([]byte(nil), orig...)) }
	if len(orig) > 0 {
		first, last := append([]byte(nil), orig...), append([]byte(nil), orig...)
		first[0] ^= 1
		last[len(last)-1] ^= 0x80
		*out = append(*out,
			mutation{path, "flip", set(first), undo},
			mutation{path, "flip-last", set(last), undo},
			mutation{path, "truncate", set(append([]byte(nil), orig[:len(orig)-1]...)), undo},
			mutation{path, "zero", set(make([]byte, len(orig))), undo})
	}
	*out = append(*out, mutation{path, "extend", set(append(append([]byte(nil), orig...), 0)), undo})
}

func sliceMutations(v reflect.Value, path string, out *[]mutation) {
	// restore puts back the ORIGINAL slice header, whose backing array the nested mutations' closures address
	orig := reflect.ValueOf(v.Interface())
	restore := func() { v.Set(orig) }
	with := func(f func(c reflect.Value) reflect.Value) func() {
		return func() {
			c := reflect.MakeSlice(v.Type(), orig.Len(), orig.Len())
			reflect.Copy(c, orig)
			v.Set(f(c))
		}
	}
	n := orig.Len()
	if n > 0 {
		*out = append(*out,
			mutation{path, "truncate", with(func(c reflect.Value) reflect.Value { return c.Slice(0, n-1) }), restore},
			mutation{path, "drop-first", with(func(c reflect.Value) reflect.Value { return c.Slice(1, n) }), restore},
			mutation{path, "extend", with(func(c reflect.Value) reflect.Value { return reflect.Append(c, c.Index(n-1)) }), restore},
			mutation{path, "zero", func() { v.Set(reflect.Zero(v.Type())) }, restore})
	}
	*out = append(*out, mutation{path, "extend-zero", with(func(c reflect.Value) reflect.Value { return reflect.Append(c, reflect.Zero(v.Type().Elem())) }), restore})
	for i := 0; i+1 < n; i++ {
		i := i
		*out = append(*out, mutation{fmt.Sprintf("%s[%d]", path, i), "swap-sibling", with(func(c reflect.Value) reflect.Value {
			a, b := reflect.ValueOf(c.Index(i).Interface()), reflect.ValueOf(c.Index(i+1).Interface())
			c.Index(i).Set(b)
			c.Index(i + 1).Set(a)
			return c
		}), restore})
	}
	if n > 1 {
		*out = append(*out, mutation{path, "reorder", with(func(c reflect.Value) reflect.Value {
			r := reflect.MakeSlice(v.Type(), n, n)
			for i := 0; i < n; i++ {
				r.Index(i).Set(c.Index(n - 1 - i))
			}
			return r
		}), restore})
	}
}

// fieldPaths is the census: every leaf field path of a type, with slice indices erased.
func fieldPaths(t reflect.Type, path string, out map[string]bool) {
	switch t.Kind() {
	case reflect.Pointer:
		out[path] = true
		fieldPaths(t.Elem(), path, out)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			fieldPaths(t.Field(i).Type, join(path, t.Field(i).Name), out)
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			out[path] = true
			return
		}
		out[path] = true
		fieldPaths(t.Elem(), path+"[]", out)
	default:
		out[path] = true
	}
}

// missing is the census check: the type's field paths that no effective mutation touched.
func missing(t reflect.Type, covered map[string]bool) []string {
	all := map[string]bool{}
	fieldPaths(t, "", all)
	var miss []string
	for p := range all {
		if !covered[p] {
			miss = append(miss, p)
		}
	}
	sort.Strings(miss)
	return miss
}

// sameChain compares two chains as their encodings, with an empty list and an absent one treated alike (they are the same proof).
func sameChain(t *testing.T, a, b *l0proof.L0ProofChain) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(bytes.ReplaceAll(ja, []byte("null"), []byte("[]")), bytes.ReplaceAll(jb, []byte("null"), []byte("[]")))
}

func TestTSALL_EveryFieldOfTheL0ProofChainIsTamperEvident(t *testing.T) {
	covered := map[string]bool{}
	total := 0
	for _, f := range fixtures(t) {
		c := clone(t, f.chain)
		mustVerify(t, f, c, f.exp, f.opts)
		before := clone(t, c)
		var ms []mutation
		mutations(reflect.ValueOf(c).Elem(), "", &ms)
		for _, m := range ms {
			m.apply()
			changed := !sameChain(t, c, before)
			if changed {
				r := l0proof.Verify(c, f.exp, f.opts)
				if r.Verified {
					t.Errorf("%s: %s of %s still verifies", f.name, m.kind, m.path)
				}
				covered[typePath(m.path)] = true
				total++
			}
			m.undo()
			if !reflect.DeepEqual(c, before) {
				t.Fatalf("%s: undoing %s of %s did not restore the chain", f.name, m.kind, m.path)
			}
		}
		mustVerify(t, f, c, f.exp, f.opts)
	}
	if miss := missing(reflect.TypeOf(l0proof.L0ProofChain{}), covered); len(miss) > 0 {
		t.Fatalf("the census found %d field(s) with no effective mutation: %s", len(miss), strings.Join(miss, ", "))
	}
	t.Logf("%d mutations over %d field paths, every one refused", total, len(covered))
}

// The census has teeth: a type with a field the fixtures never populate is reported, and an unsupported kind stops the generator by name.
func TestTSALL_TheCensusBitesAFieldWithNoMutation(t *testing.T) {
	type extended struct {
		l0proof.L0ProofChain
		Added []byte
	}
	covered := map[string]bool{}
	for p := range func() map[string]bool {
		m := map[string]bool{}
		fieldPaths(reflect.TypeOf(l0proof.L0ProofChain{}), "L0ProofChain", m)
		return m
	}() {
		covered[p] = true
	}
	miss := missing(reflect.TypeOf(extended{}), covered)
	if len(miss) != 1 || miss[0] != "Added" {
		t.Fatalf("the census did not report exactly the new field: %v", miss)
	}
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "no mutation for Weird") {
			t.Fatalf("an unsupported kind was not refused by name: %v", r)
		}
	}()
	var ms []mutation
	mutations(reflect.ValueOf(&struct{ Weird map[string]int }{map[string]int{"a": 1}}).Elem(), "", &ms)
}
