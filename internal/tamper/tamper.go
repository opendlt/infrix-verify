// Copyright 2026 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package tamper is the TS-ALL tamper generator and reflection census, shared by every proof structure's tests (govproof, verifykit): it walks every
// field of a value and, for each, flips a bit, truncates, extends, reorders, swaps with a sibling and zeroes; the census lists the field paths of a TYPE
// that no effective mutation touched, so a field added later without a mutation turns the calling test red. It is the generator of l0proof's TS-ALL test
// (brief 28bg), lifted into a package so each structure's census runs the same walker. It is imported by tests only.
package tamper

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Mutation is one change to one field: apply makes it, undo reverts it.
type Mutation struct {
	Path, Kind string
	Apply      func()
	Undo       func()
}

// TypePath is a field path with slice indices erased ("Consensus[].Header.AppHash"), which is what the census compares.
func TypePath(p string) string {
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

// Mutations enumerates the mutations of every field reachable from v.
func Mutations(v reflect.Value, path string, out *[]Mutation) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		orig := v.Elem()
		*out = append(*out, Mutation{Path: path, Kind: "zero", Apply: func() { v.Set(reflect.Zero(v.Type())) }, Undo: func() { v.Set(orig.Addr()) }})
		Mutations(v.Elem(), path, out)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			Mutations(v.Field(i), join(path, v.Type().Field(i).Name), out)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			bytesMutations(v, path, out)
			return
		}
		sliceMutations(v, path, out)
		for i := 0; i < v.Len(); i++ {
			Mutations(v.Index(i), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.String:
		s := v.String()
		set := func(x string) func() { return func() { v.SetString(x) } }
		undo := set(s)
		if s != "" {
			*out = append(*out,
				Mutation{path, "flip", set(string(s[0]^1) + s[1:]), undo},
				Mutation{path, "truncate", set(s[:len(s)-1]), undo},
				Mutation{path, "zero", set(""), undo})
		}
		*out = append(*out, Mutation{path, "extend", set(s + "x"), undo})
	case reflect.Bool:
		b := v.Bool()
		*out = append(*out, Mutation{path, "flip", func() { v.SetBool(!b) }, func() { v.SetBool(b) }})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		undo := func() { v.SetInt(n) }
		*out = append(*out, Mutation{path, "flip", func() { v.SetInt(n ^ 1) }, undo}, Mutation{path, "zero", func() { v.SetInt(0) }, undo},
			Mutation{path, "extend", func() { v.SetInt(n + 1<<20) }, undo})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		undo := func() { v.SetUint(n) }
		*out = append(*out, Mutation{path, "flip", func() { v.SetUint(n ^ 1) }, undo}, Mutation{path, "zero", func() { v.SetUint(0) }, undo})
	default:
		panic(fmt.Sprintf("the tamper generator has no mutation for %s (%s): add one", path, v.Kind()))
	}
}

func bytesMutations(v reflect.Value, path string, out *[]Mutation) {
	orig := append([]byte(nil), v.Bytes()...)
	set := func(b []byte) func() { return func() { v.SetBytes(b) } }
	undo := func() { v.SetBytes(append([]byte(nil), orig...)) }
	if len(orig) > 0 {
		first, last := append([]byte(nil), orig...), append([]byte(nil), orig...)
		first[0] ^= 1
		last[len(last)-1] ^= 0x80
		*out = append(*out,
			Mutation{path, "flip", set(first), undo},
			Mutation{path, "flip-last", set(last), undo},
			Mutation{path, "truncate", set(append([]byte(nil), orig[:len(orig)-1]...)), undo},
			Mutation{path, "zero", set(make([]byte, len(orig))), undo})
	}
	*out = append(*out, Mutation{path, "extend", set(append(append([]byte(nil), orig...), 0)), undo})
}

func sliceMutations(v reflect.Value, path string, out *[]Mutation) {
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
			Mutation{path, "truncate", with(func(c reflect.Value) reflect.Value { return c.Slice(0, n-1) }), restore},
			Mutation{path, "drop-first", with(func(c reflect.Value) reflect.Value { return c.Slice(1, n) }), restore},
			Mutation{path, "extend", with(func(c reflect.Value) reflect.Value { return reflect.Append(c, c.Index(n-1)) }), restore},
			Mutation{path, "zero", func() { v.Set(reflect.Zero(v.Type())) }, restore})
	}
	*out = append(*out, Mutation{path, "extend-zero", with(func(c reflect.Value) reflect.Value { return reflect.Append(c, reflect.Zero(v.Type().Elem())) }), restore})
	for i := 0; i+1 < n; i++ {
		i := i
		*out = append(*out, Mutation{fmt.Sprintf("%s[%d]", path, i), "swap-sibling", with(func(c reflect.Value) reflect.Value {
			a, b := reflect.ValueOf(c.Index(i).Interface()), reflect.ValueOf(c.Index(i+1).Interface())
			c.Index(i).Set(b)
			c.Index(i + 1).Set(a)
			return c
		}), restore})
	}
	if n > 1 {
		*out = append(*out, Mutation{path, "reorder", with(func(c reflect.Value) reflect.Value {
			r := reflect.MakeSlice(v.Type(), n, n)
			for i := 0; i < n; i++ {
				r.Index(i).Set(c.Index(n - 1 - i))
			}
			return r
		}), restore})
	}
}

// FieldPaths is the census: every leaf field path of a type, with slice indices erased.
func FieldPaths(t reflect.Type, path string, out map[string]bool) {
	switch t.Kind() {
	case reflect.Pointer:
		out[path] = true
		FieldPaths(t.Elem(), path, out)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			FieldPaths(t.Field(i).Type, join(path, t.Field(i).Name), out)
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			out[path] = true
			return
		}
		out[path] = true
		FieldPaths(t.Elem(), path+"[]", out)
	default:
		out[path] = true
	}
}

// Missing is the census check: the type's field paths that no effective mutation touched.
func Missing(t reflect.Type, covered map[string]bool) []string {
	all := map[string]bool{}
	FieldPaths(t, "", all)
	var miss []string
	for p := range all {
		if !covered[p] {
			miss = append(miss, p)
		}
	}
	sort.Strings(miss)
	return miss
}
