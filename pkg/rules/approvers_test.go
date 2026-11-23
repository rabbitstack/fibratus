/*
 * Copyright 2026 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rules

import (
	"sort"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	pathKey = Key{Field: fields.FilePath}
	extKey  = Key{Field: fields.FileExtension}
	opKey   = Key{Field: fields.FileOperation} // the selector of the CreateFile events
	regKey  = Key{Field: fields.RegistryPath}
	psKey   = Key{Field: fields.PsName}
	exeKey  = Key{Field: fields.EvtArg, Arg: params.Exe}

	// the scope of the CreateFile events with the OPEN disposition
	openScope   = Scope{Type: event.CreateFile, Selector: "OPEN"}
	createScope = Scope{Type: event.CreateFile, Selector: "CREATE"}
	regScope    = Scope{Type: event.RegOpenKey}
)

// mapResolver resolves the keys from a map and records the keys it was asked for.
type mapResolver struct {
	values map[Key]string
	asked  []Key
}

func (r *mapResolver) Resolve(k Key) (string, bool) {
	r.asked = append(r.asked, k)
	v, ok := r.values[k]
	return v, ok
}

func resolver(values map[Key]string) *mapResolver { return &mapResolver{values: values} }

// file resolves the attributes of the CreateFile event.
func file(operation, path string) *mapResolver {
	return resolver(map[Key]string{opKey: operation, pathKey: path})
}

// leaf builds the `field op value` comparison.
func leaf(op lexer.Token, key Key, vals ...string) *ast.BinaryExpr {
	var rhs ast.Expr = &ast.ListLiteral{Values: vals}
	if len(vals) == 1 {
		rhs = &ast.StringLiteral{Value: vals[0]}
	}
	return &ast.BinaryExpr{
		Op:  op,
		LHS: &ast.FieldLiteral{Field: key.Field, Arg: key.Arg},
		RHS: rhs,
	}
}

func and(l, r ast.Expr) *ast.BinaryExpr { return &ast.BinaryExpr{Op: lexer.And, LHS: l, RHS: r} }
func or(l, r ast.Expr) *ast.BinaryExpr  { return &ast.BinaryExpr{Op: lexer.Or, LHS: l, RHS: r} }
func not(e ast.Expr) *ast.NotExpr       { return &ast.NotExpr{Expr: e} }
func paren(e ast.Expr) *ast.ParenExpr   { return &ast.ParenExpr{Expr: e} }

// open is the file.operation = 'OPEN' comparison.
func open() *ast.BinaryExpr { return leaf(lexer.Eq, opKey, "OPEN") }

func fixedTypes(types ...event.Type) func(ast.Expr) ([]event.Type, bool) {
	return func(ast.Expr) ([]event.Type, bool) { return types, true }
}

func unknownTypes(ast.Expr) ([]event.Type, bool) { return nil, false }

// newTestBuilder returns the builder that believes the expressions consume the given event types.
func newTestBuilder(caps ApproverCaps, types ...event.Type) *builder {
	b := newBuilder(caps)
	b.typesOf = fixedTypes(types...)
	return b
}

func fieldMatcher(t *testing.T, key Key, op lexer.Token, vals ...string) FieldMatcher {
	t.Helper()
	return FieldMatcher{Key: key, Matcher: mustMatcher(t, op, vals...), cost: opCost(op)}
}

func approverOf(t *testing.T, key Key, op lexer.Token, vals ...string) Approver {
	t.Helper()
	return Approver{Matchers: []FieldMatcher{fieldMatcher(t, key, op, vals...)}}
}

func TestKeyString(t *testing.T) {
	assert.Equal(t, string(fields.FilePath), pathKey.String())
	assert.Equal(t, string(fields.EvtArg)+"["+params.Exe+"]", exeKey.String())
	assert.True(t, Key{}.isZero())
	assert.False(t, opKey.isZero())
}

func TestApproverApprove(t *testing.T) {
	ap := Approver{Matchers: []FieldMatcher{
		fieldMatcher(t, extKey, lexer.IIn, ".dll", ".exe"),
		fieldMatcher(t, pathKey, lexer.IMatches, `C:\Windows\*`),
	}}

	t.Run("all matchers pass", func(t *testing.T) {
		r := resolver(map[Key]string{extKey: ".DLL", pathKey: `C:\Windows\a.dll`})
		assert.True(t, ap.Approve(r))
	})

	t.Run("a matcher rejects", func(t *testing.T) {
		r := resolver(map[Key]string{extKey: ".dll", pathKey: `D:\a.dll`})
		assert.False(t, ap.Approve(r))
	})

	t.Run("rejects without resolving the remaining attributes", func(t *testing.T) {
		r := resolver(map[Key]string{extKey: ".txt", pathKey: `C:\Windows\a.txt`})
		assert.False(t, ap.Approve(r))
		assert.Equal(t, []Key{extKey}, r.asked)
	})

	t.Run("unresolved attribute doesn't reject", func(t *testing.T) {
		r := resolver(map[Key]string{pathKey: `C:\Windows\a.dll`})
		assert.True(t, ap.Approve(r))

		r = resolver(map[Key]string{pathKey: `D:\a.dll`})
		assert.False(t, ap.Approve(r), "the resolved attribute still decides")

		assert.True(t, ap.Approve(resolver(nil)))
	})

	t.Run("empty approver approves", func(t *testing.T) {
		assert.True(t, Approver{}.Approve(resolver(nil)))
	})
}

func TestApproverString(t *testing.T) {
	ap := Approver{Matchers: []FieldMatcher{
		fieldMatcher(t, extKey, lexer.Eq, ".exe"),
		fieldMatcher(t, pathKey, lexer.IMatches, `C:\*`),
	}}
	assert.Equal(t, string(fields.FileExtension)+" = '.exe' and "+string(fields.FilePath)+` imatches ('C:\*')`, ap.String())
	assert.Equal(t, "", Approver{}.String())
}

func TestApproversNil(t *testing.T) {
	var a *Approvers

	assert.True(t, a.Approve(event.CreateFile, resolver(nil)))
	assert.False(t, a.Narrows(openScope))
	assert.Nil(t, a.For(openScope))
	assert.Nil(t, a.AcceptAllRule(openScope))
	assert.Empty(t, a.Scopes())
	assert.Empty(t, a.String())
}

// Only the CreateFile events with the OPEN disposition are narrowed down by the path.
func TestApproversApproveByScope(t *testing.T) {
	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, approverOf(t, pathKey, lexer.IMatches, `C:\Windows\*`), &Rule{})
	a := b.build()

	tests := []struct {
		name string
		r    Resolver
		want bool
	}{
		{"open of a matching path", file("OPEN", `C:\Windows\a.dll`), true},
		{"open of another path", file("OPEN", `D:\a.dll`), false},
		{"other dispositions aren't narrowed down", file("CREATE", `D:\a.dll`), true},
		{"the selector is compared exactly", file("open", `D:\a.dll`), true},
		{"unresolved selector doesn't reject", resolver(map[Key]string{pathKey: `D:\a.dll`}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Approve(event.CreateFile, tt.r))
		})
	}

	t.Run("the path isn't resolved for the scopes that aren't narrowed down", func(t *testing.T) {
		r := file("CREATE", `D:\a.dll`)
		assert.True(t, a.Approve(event.CreateFile, r))
		assert.Equal(t, []Key{opKey}, r.asked)
	})

	t.Run("types that have no approvers are approved", func(t *testing.T) {
		assert.True(t, a.Approve(event.RegOpenKey, resolver(nil)))
		assert.True(t, a.Approve(event.CreateProcess, resolver(nil)))
	})
}

func TestApproversApproveIfAnyApproverApproves(t *testing.T) {
	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, approverOf(t, pathKey, lexer.IStartswith, `c:\windows\`), &Rule{})
	b.add(openScope, approverOf(t, pathKey, lexer.IEndswith, `.ps1`), &Rule{})
	a := b.build()

	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `C:\Windows\a.dll`)))
	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\scripts\a.ps1`)))
	assert.False(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
}

func TestApproversQueries(t *testing.T) {
	rule := &Rule{}
	narrowing := approverOf(t, pathKey, lexer.IMatches, `C:\Windows\*`)

	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, narrowing, rule)
	b.acceptAll(regScope, rule)
	a := b.build()

	t.Run("narrows", func(t *testing.T) {
		assert.True(t, a.Narrows(openScope))
		assert.False(t, a.Narrows(createScope), "no approvers registered")
		assert.False(t, a.Narrows(regScope), "accept-all mode")
		assert.False(t, a.Narrows(Scope{Type: event.OpenProcess}), "no approvers registered")
	})

	t.Run("for", func(t *testing.T) {
		assert.Len(t, a.For(openScope), 1)
		assert.Nil(t, a.For(createScope))
		assert.Nil(t, a.For(regScope))
	})

	t.Run("accept-all rule", func(t *testing.T) {
		assert.Same(t, rule, a.AcceptAllRule(regScope))
		assert.Nil(t, a.AcceptAllRule(openScope))
		assert.Nil(t, a.AcceptAllRule(createScope))
	})

	t.Run("scopes are sorted", func(t *testing.T) {
		scopes := a.Scopes()
		require.ElementsMatch(t, []Scope{openScope, regScope}, scopes)
		assert.True(t, sort.SliceIsSorted(scopes, func(i, j int) bool {
			return scopes[i].Type.String() < scopes[j].Type.String()
		}))
	})

	t.Run("string", func(t *testing.T) {
		s := a.String()
		assert.Contains(t, s, event.RegOpenKey.String()+": all")
		assert.Contains(t, s, event.CreateFile.String()+"["+opKey.String()+" = 'OPEN']: ("+narrowing.String()+")")
	})
}

func TestBuilderAcceptAll(t *testing.T) {
	first, second, third := &Rule{}, &Rule{}, &Rule{}
	narrowing := approverOf(t, pathKey, lexer.Eq, `C:\a`)

	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, narrowing, first)
	b.add(regScope, narrowing, first)

	// an approver without predicates can't narrow down the events
	b.add(openScope, Approver{}, second)
	a := b.build()
	assert.False(t, a.Narrows(openScope))
	assert.Nil(t, a.For(openScope))
	assert.Same(t, second, a.AcceptAllRule(openScope))
	assert.True(t, a.Narrows(regScope), "the other scopes are unaffected")

	// accept-all can't be undone by later approvers, and the first rule responsible is kept
	b.add(openScope, narrowing, first)
	b.acceptAll(openScope, third)
	a = b.build()
	assert.False(t, a.Narrows(openScope))
	assert.Same(t, second, a.AcceptAllRule(openScope))
}

func TestBuilderIsUsableAfterBuild(t *testing.T) {
	apA := approverOf(t, pathKey, lexer.IStartswith, `c:\a\`)
	apB := approverOf(t, pathKey, lexer.IStartswith, `c:\b\`)

	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, apB, &Rule{})
	b.add(openScope, apA, &Rule{})
	b.add(openScope, apA, &Rule{})
	assert.Len(t, b.build().For(openScope), 2)

	b.add(openScope, approverOf(t, pathKey, lexer.IStartswith, `c:\c\`), &Rule{})
	assert.Len(t, b.build().For(openScope), 3)
}

func TestBuildDeduplicatesAndSortsApprovers(t *testing.T) {
	apA := approverOf(t, pathKey, lexer.IStartswith, `c:\a\`)
	apB := approverOf(t, pathKey, lexer.IStartswith, `c:\b\`)

	b := newBuilder(DefaultApproverCaps())
	b.add(openScope, apB, &Rule{})
	b.add(openScope, apA, &Rule{})
	b.add(openScope, apB, &Rule{})
	b.add(openScope, apA, &Rule{})
	a := b.build()

	aps := a.For(openScope)
	require.Len(t, aps, 2)
	assert.Equal(t, apA.String(), aps[0].String(), "ordered by their text, so the output is stable")
	assert.Equal(t, apB.String(), aps[1].String())
}

func TestEventTypes(t *testing.T) {
	caps := ApproverCaps{
		Events: map[event.Type]EventCaps{
			event.CreateFile:  unscoped(pathKey),
			event.RegOpenKey:  unscoped(regKey),
			event.OpenProcess: unscoped(exeKey),
		},
		DependsOn: map[event.Type][]event.Type{
			event.CreateFile: {event.RegOpenKey}, // mentioned in both maps
			event.DeleteFile: {event.CreateFile},
		},
	}

	types := caps.eventTypes()
	assert.ElementsMatch(t, []event.Type{event.CreateFile, event.RegOpenKey, event.OpenProcess, event.DeleteFile}, types)
	assert.Equal(t, types, caps.eventTypes(), "deterministic")
}

func TestConjuncts(t *testing.T) {
	b := newBuilder(ApproverCaps{})
	l1 := open()
	l2 := leaf(lexer.IMatches, pathKey, `C:\*`)
	l3 := leaf(lexer.IEq, regKey, `HKLM\x`)

	tests := []struct {
		name string
		expr ast.Expr
		want []*ast.BinaryExpr
	}{
		{"single comparison", l1, []*ast.BinaryExpr{l1}},
		{"and", and(l1, l2), []*ast.BinaryExpr{l1, l2}},
		{"nested and", and(and(l1, l2), l3), []*ast.BinaryExpr{l1, l2, l3}},
		{"parentheses", paren(and(l1, l2)), []*ast.BinaryExpr{l1, l2}},
		{"and with parenthesized and", and(l1, paren(and(l2, l3))), []*ast.BinaryExpr{l1, l2, l3}},
		// comparisons under OR aren't necessary conditions
		{"or", or(l1, l2), nil},
		{"or under and keeps the sibling", and(l1, or(l2, l3)), []*ast.BinaryExpr{l1}},
		{"parenthesized or", paren(or(l1, l2)), nil},
		// neither are the negated ones
		{"not", not(l2), nil},
		{"not under and keeps the sibling", and(l1, not(l2)), []*ast.BinaryExpr{l1}},
		{"not of a conjunction", and(l1, not(and(l2, l3))), []*ast.BinaryExpr{l1}},
		{"parenthesized not", and(l1, paren(not(l2))), []*ast.BinaryExpr{l1}},
		{"not a binary expression", &ast.StringLiteral{Value: "x"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, b.conjuncts(tt.expr, nil))
		})
	}
}

func TestLiteralValues(t *testing.T) {
	b := newBuilder(ApproverCaps{})

	vals, ok := b.literalValues(&ast.StringLiteral{Value: "a"})
	assert.True(t, ok)
	assert.Equal(t, []string{"a"}, vals)

	vals, ok = b.literalValues(&ast.ListLiteral{Values: []string{"a", "b"}})
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b"}, vals)

	_, ok = b.literalValues(&ast.FieldLiteral{Field: fields.FilePath})
	assert.False(t, ok, "the comparison against another field can't be evaluated early")
}

func TestApprover(t *testing.T) {
	b := newBuilder(DefaultApproverCaps())
	openKeys := DefaultApproverCaps().Events[event.CreateFile].Keys["OPEN"]

	t.Run("keeps the comparisons the event source can resolve", func(t *testing.T) {
		ap := b.approver([]*ast.BinaryExpr{
			leaf(lexer.IMatches, pathKey, `C:\Windows\*`),
			leaf(lexer.IIn, extKey, ".dll", ".exe"),
		}, openKeys)

		require.Len(t, ap.Matchers, 2)
		// cheap predicates are evaluated first
		assert.Equal(t, extKey, ap.Matchers[0].Key)
		assert.Equal(t, pathKey, ap.Matchers[1].Key)
	})

	t.Run("the selector is not a predicate", func(t *testing.T) {
		ap := b.approver([]*ast.BinaryExpr{open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)}, openKeys)

		require.Len(t, ap.Matchers, 1)
		assert.Equal(t, pathKey, ap.Matchers[0].Key)
	})

	t.Run("skips what can't be approved", func(t *testing.T) {
		ap := b.approver([]*ast.BinaryExpr{
			leaf(lexer.Eq, regKey, `HKLM\x`),   // the key isn't available for the scope
			leaf(lexer.Contains, pathKey, "x"), // case-sensitive contains
			{Op: lexer.Eq, LHS: &ast.StringLiteral{Value: "a"}, RHS: leaf(lexer.Eq, pathKey, "b")}, // not a field on the left
			{Op: lexer.Eq, LHS: &ast.FieldLiteral{Field: fields.FilePath}, RHS: &ast.FieldLiteral{Field: fields.FileName}},
		}, openKeys)
		assert.Empty(t, ap.Matchers)
	})

	t.Run("event argument keys match the argument name", func(t *testing.T) {
		keys := DefaultApproverCaps().Events[event.OpenProcess].Keys[""]

		ap := b.approver([]*ast.BinaryExpr{leaf(lexer.IEndswith, exeKey, `\lsass.exe`)}, keys)
		require.Len(t, ap.Matchers, 1)
		assert.Equal(t, exeKey, ap.Matchers[0].Key)

		other := Key{Field: fields.EvtArg, Arg: "pid"}
		ap = b.approver([]*ast.BinaryExpr{leaf(lexer.Eq, other, "1")}, keys)
		assert.Empty(t, ap.Matchers)
	})
}

func TestSelection(t *testing.T) {
	b := newBuilder(ApproverCaps{})
	path := leaf(lexer.IMatches, pathKey, `C:\*`)

	tests := []struct {
		name     string
		selector Key
		leaves   []*ast.BinaryExpr
		want     selection
	}{
		{"type without a selector", Key{}, []*ast.BinaryExpr{path}, selectsExactly},
		{"type without a selector and no comparisons", Key{}, nil, selectsExactly},

		{"equals", opKey, []*ast.BinaryExpr{open()}, selectsExactly},
		{"equals among other comparisons", opKey, []*ast.BinaryExpr{path, open()}, selectsExactly},
		{"ieq", opKey, []*ast.BinaryExpr{leaf(lexer.IEq, opKey, "open")}, selectsExactly},

		{"another value", opKey, []*ast.BinaryExpr{leaf(lexer.Eq, opKey, "CREATE")}, selectsNone},
		{"another value, ignoring the case", opKey, []*ast.BinaryExpr{leaf(lexer.IEq, opKey, "create")}, selectsNone},
		{"equals is case-sensitive", opKey, []*ast.BinaryExpr{leaf(lexer.Eq, opKey, "open")}, selectsNone},
		{"not in the list", opKey, []*ast.BinaryExpr{leaf(lexer.In, opKey, "CREATE", "SUPERSEDE")}, selectsNone},
		{"contradicting comparisons", opKey, []*ast.BinaryExpr{open(), leaf(lexer.Eq, opKey, "CREATE")}, selectsNone},
		{"contradicting comparisons, reversed", opKey, []*ast.BinaryExpr{leaf(lexer.Eq, opKey, "CREATE"), open()}, selectsNone},

		// only the = and ieq operators pin the selector
		{"in the list", opKey, []*ast.BinaryExpr{leaf(lexer.In, opKey, "OPEN", "CREATE")}, selectsSome},
		{"in a list of one", opKey, []*ast.BinaryExpr{leaf(lexer.In, opKey, "OPEN")}, selectsSome},
		{"iin", opKey, []*ast.BinaryExpr{leaf(lexer.IIn, opKey, "open")}, selectsSome},
		{"pattern", opKey, []*ast.BinaryExpr{leaf(lexer.IMatches, opKey, "OP*")}, selectsSome},
		{"pinned and in the list", opKey, []*ast.BinaryExpr{leaf(lexer.In, opKey, "OPEN", "CREATE"), open()}, selectsExactly},

		{"no comparison on the selector", opKey, []*ast.BinaryExpr{path}, selectsSome},
		{"no comparisons at all", opKey, nil, selectsSome},
		{"operator that can't be evaluated", opKey, []*ast.BinaryExpr{leaf(lexer.Contains, opKey, "OPEN")}, selectsSome},
		{"operand that isn't a literal", opKey, []*ast.BinaryExpr{{
			Op: lexer.Eq, LHS: &ast.FieldLiteral{Field: fields.FileOperation}, RHS: &ast.FieldLiteral{Field: fields.FilePath},
		}}, selectsSome},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, b.selection(tt.selector, "OPEN", tt.leaves))
		})
	}
}

// evt.name = 'CreateFile' and file.operation = 'OPEN' and file.path imatches '...'
func TestAddExprPinnedSelectorNarrowsScope(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	a := b.build()

	assert.Equal(t, []Scope{openScope}, a.Scopes(), "no other scope is registered")
	require.True(t, a.Narrows(openScope))

	aps := a.For(openScope)
	require.Len(t, aps, 1)
	require.Len(t, aps[0].Matchers, 1, "the selector isn't an approver predicate")
	assert.Equal(t, pathKey, aps[0].Matchers[0].Key)

	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `C:\Windows\a.dll`)))
	assert.False(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
	assert.True(t, a.Approve(event.CreateFile, file("CREATE", `D:\a.dll`)))
}

func TestAddExprSelectorForms(t *testing.T) {
	tests := []struct {
		name   string
		expr   ast.Expr
		narrow bool
	}{
		{"= pins the selector", and(open(), leaf(lexer.IMatches, pathKey, `C:\*`)), true},
		{"ieq pins the selector", and(leaf(lexer.IEq, opKey, "open"), leaf(lexer.IMatches, pathKey, `C:\*`)), true},
		{"parentheses", and(paren(open()), paren(leaf(lexer.IMatches, pathKey, `C:\*`))), true},
		{"predicates before the selector", and(leaf(lexer.IMatches, pathKey, `C:\*`), open()), true},

		// the path of a rule that doesn't pin the selector can't narrow the scope
		{"no selector comparison", leaf(lexer.IMatches, pathKey, `C:\*`), false},
		{"in a list", and(leaf(lexer.In, opKey, "OPEN", "CREATE"), leaf(lexer.IMatches, pathKey, `C:\*`)), false},
		{"pattern", and(leaf(lexer.IMatches, opKey, "OP*"), leaf(lexer.IMatches, pathKey, `C:\*`)), false},
		{"negated selector", and(not(open()), leaf(lexer.IMatches, pathKey, `C:\*`)), false},
		{"selector under or", and(or(open(), leaf(lexer.Eq, opKey, "CREATE")), leaf(lexer.IMatches, pathKey, `C:\*`)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &Rule{}
			b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
			b.addExpr(rule, tt.expr)
			a := b.build()

			assert.Equal(t, tt.narrow, a.Narrows(openScope))
			if !tt.narrow {
				assert.Same(t, rule, a.AcceptAllRule(openScope))
				assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
			}
		})
	}
}

// The rules that can't consume the OPEN events have no say on them.
func TestAddExprOtherSelectorValuesDontAffectScope(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	b.addExpr(&Rule{}, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IMatches, pathKey, `D:\*`)))
	b.addExpr(&Rule{}, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IEq, psKey, "cmd.exe")))
	a := b.build()

	assert.Equal(t, []Scope{openScope}, a.Scopes())
	assert.Len(t, a.For(openScope), 1)
	assert.False(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
}

// file.path not imatches '...' can't contribute a path.
func TestAddExprNegationsYieldNoPaths(t *testing.T) {
	t.Run("only negated paths", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(rule, and(open(), not(leaf(lexer.IMatches, pathKey, `C:\Windows\*`))))
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
		assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
	})

	t.Run("negated conjunction", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(rule, and(open(), not(and(leaf(lexer.IMatches, pathKey, `C:\Windows\*`), leaf(lexer.IIn, extKey, ".dll")))))
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
	})

	t.Run("negated path next to a positive one", func(t *testing.T) {
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(&Rule{}, and(open(), and(
			leaf(lexer.IMatches, pathKey, `C:\Windows\*`),
			not(leaf(lexer.IMatches, pathKey, `C:\Windows\Temp\*`)),
		)))
		a := b.build()

		aps := a.For(openScope)
		require.Len(t, aps, 1)
		require.Len(t, aps[0].Matchers, 1)
		assert.Contains(t, aps[0].String(), `C:\Windows\*`)
		assert.NotContains(t, aps[0].String(), `Temp`)

		// the negation can't reject anything, the rule itself does that later
		assert.True(t, a.Approve(event.CreateFile, file("OPEN", `C:\Windows\Temp\a.dll`)))
	})

	t.Run("negated paths under a parenthesized not", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(rule, and(open(), paren(not(leaf(lexer.IMatches, pathKey, `C:\*`)))))
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
	})
}

func TestAddExprOrYieldsNoPaths(t *testing.T) {
	rule := &Rule{}
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(rule, and(open(), paren(or(leaf(lexer.IMatches, pathKey, `C:\a\*`), leaf(lexer.IMatches, pathKey, `C:\b\*`)))))
	a := b.build()

	assert.False(t, a.Narrows(openScope))
	assert.Same(t, rule, a.AcceptAllRule(openScope))
}

// The rule that consumes the OPEN events with a predicate that can't be evaluated
// early forces every OPEN event to be approved, whatever the other rules say.
func TestAddExprRuleWithoutPathAcceptsAllOpens(t *testing.T) {
	rule := &Rule{}
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	b.addExpr(rule, and(open(), leaf(lexer.IEq, psKey, "cmd.exe")))
	a := b.build()

	assert.False(t, a.Narrows(openScope))
	assert.Same(t, rule, a.AcceptAllRule(openScope))
	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))

	// the order of the rules doesn't matter
	b = newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(rule, and(open(), leaf(lexer.IEq, psKey, "cmd.exe")))
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	a = b.build()

	assert.False(t, a.Narrows(openScope))
	assert.Same(t, rule, a.AcceptAllRule(openScope))
}

// The rule that doesn't mention the selector consumes the events of every scope.
func TestAddExprRuleWithoutSelectorAcceptsAllOpens(t *testing.T) {
	rule := &Rule{}
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	b.addExpr(rule, leaf(lexer.IMatches, pathKey, `D:\*`))
	a := b.build()

	assert.False(t, a.Narrows(openScope))
	assert.Same(t, rule, a.AcceptAllRule(openScope))
	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
}

func TestAddExprRulesAreOred(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IEndswith, pathKey, `.ps1`)))
	a := b.build()

	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `C:\Windows\a.dll`)))
	assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.ps1`)))
	assert.False(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
}

func TestAddExprDeduplicatesIdenticalRules(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	b.addExpr(&Rule{}, and(leaf(lexer.IEq, opKey, "open"), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))

	assert.Len(t, b.build().For(openScope), 1)
}

func TestAddExprTypeWithoutSelector(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.RegOpenKey)
	b.addExpr(&Rule{}, leaf(lexer.IMatches, regKey, `HKLM\Software\*`))
	a := b.build()

	assert.Equal(t, []Scope{regScope}, a.Scopes())
	require.True(t, a.Narrows(regScope))
	assert.True(t, a.Approve(event.RegOpenKey, resolver(map[Key]string{regKey: `HKLM\Software\a`})))
	assert.False(t, a.Approve(event.RegOpenKey, resolver(map[Key]string{regKey: `HKCU\a`})))
}

func TestAddExprTypeWithoutSelectorNegation(t *testing.T) {
	rule := &Rule{}
	b := newTestBuilder(DefaultApproverCaps(), event.RegOpenKey)
	b.addExpr(rule, not(leaf(lexer.IMatches, regKey, `HKLM\Software\*`)))
	a := b.build()

	assert.False(t, a.Narrows(regScope))
	assert.Same(t, rule, a.AcceptAllRule(regScope))
}

// Every selector value is a scope of its own.
func TestAddExprScopesAreIndependent(t *testing.T) {
	caps := ApproverCaps{Events: map[event.Type]EventCaps{
		event.CreateFile: {
			Selector: opKey,
			Keys: map[string][]Key{
				"OPEN":   {pathKey},
				"CREATE": {pathKey},
			},
		},
	}}

	t.Run("each rule only joins the scope it pins", func(t *testing.T) {
		b := newTestBuilder(caps, event.CreateFile)
		b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\open\*`)))
		b.addExpr(&Rule{}, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IMatches, pathKey, `C:\create\*`)))
		a := b.build()

		assert.True(t, a.Narrows(openScope))
		assert.True(t, a.Narrows(createScope))
		assert.True(t, a.Approve(event.CreateFile, file("OPEN", `C:\open\a`)))
		assert.False(t, a.Approve(event.CreateFile, file("OPEN", `C:\create\a`)))
		assert.True(t, a.Approve(event.CreateFile, file("CREATE", `C:\create\a`)))
		assert.False(t, a.Approve(event.CreateFile, file("CREATE", `C:\open\a`)))
		// the scopes that aren't listed in the capabilities are never narrowed down
		assert.True(t, a.Approve(event.CreateFile, file("OVERWRITE", `C:\other\a`)))
	})

	t.Run("a rule that spans the scopes forces all of them", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(caps, event.CreateFile)
		b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\open\*`)))
		b.addExpr(&Rule{}, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IMatches, pathKey, `C:\create\*`)))
		b.addExpr(rule, leaf(lexer.IMatches, pathKey, `C:\any\*`))
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.False(t, a.Narrows(createScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
		assert.Same(t, rule, a.AcceptAllRule(createScope))
	})

	t.Run("a rule that pins one scope leaves the other alone", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(caps, event.CreateFile)
		b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\open\*`)))
		b.addExpr(&Rule{}, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IMatches, pathKey, `C:\create\*`)))
		b.addExpr(rule, and(leaf(lexer.Eq, opKey, "CREATE"), leaf(lexer.IEq, psKey, "cmd.exe")))
		a := b.build()

		assert.True(t, a.Narrows(openScope))
		assert.False(t, a.Narrows(createScope))
		assert.Same(t, rule, a.AcceptAllRule(createScope))
	})
}

func TestAddExprMultipleTypes(t *testing.T) {
	rule := &Rule{}
	b := newTestBuilder(DefaultApproverCaps(), event.CreateFile, event.RegOpenKey)

	// evt.name in ('CreateFile', 'RegOpenKey') and file.operation = 'OPEN' and file.path imatches ...
	b.addExpr(rule, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	a := b.build()

	assert.True(t, a.Narrows(openScope))
	// file.path says nothing about the registry events
	assert.False(t, a.Narrows(regScope))
	assert.Same(t, rule, a.AcceptAllRule(regScope))
}

func TestAddExprIgnoresTypesWithoutCapabilities(t *testing.T) {
	b := newTestBuilder(DefaultApproverCaps(), event.CreateProcess)
	b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))
	a := b.build()

	assert.Empty(t, a.Scopes())
	assert.True(t, a.Approve(event.CreateProcess, resolver(nil)))
	assert.False(t, a.Narrows(openScope))
}

// A rule can't make the events it consumes depend on events that were discarded,
// so the dependency is accepted regardless of the order the rules are processed.
func TestAddExprDependsOn(t *testing.T) {
	narrowing := and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`))

	t.Run("dependency registered first", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(&Rule{}, narrowing)
		b.typesOf = fixedTypes(event.DeleteFile)
		b.addExpr(rule, leaf(lexer.IMatches, pathKey, `C:\x\*`))
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
		assert.True(t, a.Approve(event.CreateFile, file("OPEN", `D:\a.dll`)))
	})

	t.Run("dependency registered last", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.RenameFile)
		b.addExpr(rule, leaf(lexer.IMatches, pathKey, `C:\x\*`))
		b.typesOf = fixedTypes(event.CreateFile)
		b.addExpr(&Rule{}, narrowing)
		a := b.build()

		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
	})

	t.Run("every scope of the dependency is accepted", func(t *testing.T) {
		caps := ApproverCaps{
			Events: map[event.Type]EventCaps{
				event.CreateFile: {Selector: opKey, Keys: map[string][]Key{"OPEN": {pathKey}, "CREATE": {pathKey}}},
			},
			DependsOn: map[event.Type][]event.Type{event.DeleteFile: {event.CreateFile}},
		}
		rule := &Rule{}
		b := newTestBuilder(caps, event.DeleteFile)
		b.addExpr(rule, leaf(lexer.IMatches, pathKey, `C:\x\*`))
		a := b.build()

		assert.ElementsMatch(t, []Scope{openScope, createScope}, a.Scopes())
		assert.Same(t, rule, a.AcceptAllRule(openScope))
		assert.Same(t, rule, a.AcceptAllRule(createScope))
	})

	t.Run("types that don't depend on anything are unaffected", func(t *testing.T) {
		b := newTestBuilder(DefaultApproverCaps(), event.RegOpenKey)
		b.addExpr(&Rule{}, leaf(lexer.IMatches, regKey, `HKLM\*`))
		a := b.build()

		assert.True(t, a.Narrows(regScope))
		assert.False(t, a.Narrows(openScope))
	})
}

// If the event types the rule consumes can't be determined the rule may consume any of
// them, so it can't be allowed to discard the events on behalf of other rules.
func TestAddExprUnknownTypes(t *testing.T) {
	t.Run("with dependencies", func(t *testing.T) {
		rule := &Rule{}
		b := newTestBuilder(DefaultApproverCaps(), event.CreateFile)
		b.addExpr(&Rule{}, and(open(), leaf(lexer.IMatches, pathKey, `C:\Windows\*`)))

		b.typesOf = unknownTypes
		b.addExpr(rule, and(open(), leaf(lexer.IMatches, pathKey, `C:\Temp\*`)))
		a := b.build()

		// the rule may consume the file deletions, which need all the file opens
		assert.False(t, a.Narrows(openScope))
		assert.Same(t, rule, a.AcceptAllRule(openScope))
		// file.path is of no use for the other types
		assert.False(t, a.Narrows(regScope))
		assert.False(t, a.Narrows(Scope{Type: event.OpenProcess}))
		assert.False(t, a.Narrows(Scope{Type: event.OpenThread}))
	})

	t.Run("without dependencies", func(t *testing.T) {
		caps := ApproverCaps{Events: map[event.Type]EventCaps{
			event.CreateFile: DefaultApproverCaps().Events[event.CreateFile],
			event.RegOpenKey: unscoped(regKey),
		}}
		rule := &Rule{}
		b := newTestBuilder(caps)
		b.typesOf = unknownTypes
		b.addExpr(rule, and(open(), leaf(lexer.IMatches, pathKey, `C:\Temp\*`)))
		a := b.build()

		// the comparisons are still necessary conditions for any scope that can resolve them
		assert.True(t, a.Narrows(openScope))
		assert.False(t, a.Approve(event.CreateFile, file("OPEN", `D:\a`)))
		// but the registry events can't be told apart
		assert.False(t, a.Narrows(regScope))
		assert.Same(t, rule, a.AcceptAllRule(regScope))
	})
}

func TestComputeApproversWithoutRules(t *testing.T) {
	a := computeApprovers(nil, DefaultApproverCaps())

	require.NotNil(t, a)
	assert.Empty(t, a.Scopes())
	assert.True(t, a.Approve(event.CreateFile, resolver(nil)))
}
