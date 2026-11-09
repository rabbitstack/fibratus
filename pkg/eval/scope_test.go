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

package eval

import (
	"strings"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type evTypes struct {
	a, b, c    event.Type
	an, bn, cn string
}

func newTypes(t *testing.T) evTypes {
	t.Helper()
	all := event.AllTypes()
	require.True(t, len(all) >= 3, "need at least three event types")
	ts := evTypes{a: all[0], b: all[1], c: all[2]}
	ts.an, ts.bn, ts.cn = ts.a.String(), ts.b.String(), ts.c.String()
	for _, name := range []string{ts.an, ts.bn, ts.cn} {
		require.NotEqual(t, name, strings.ToUpper(name), "event name has no lowercase letters: "+name)
	}
	return ts
}

var psName = fields.Field("ps.name")

func field(f fields.Field) *ast.FieldLiteral { return &ast.FieldLiteral{Value: string(f), Field: f} }
func str(s string) *ast.StringLiteral        { return &ast.StringLiteral{Value: s} }
func list(s ...string) *ast.ListLiteral      { return &ast.ListLiteral{Values: s} }
func paren(e ast.Expr) *ast.ParenExpr        { return &ast.ParenExpr{Expr: e} }
func not(e ast.Expr) *ast.NotExpr            { return &ast.NotExpr{Expr: e} }

func bin(op lexer.Token, lhs, rhs ast.Expr) *ast.BinaryExpr {
	return &ast.BinaryExpr{Op: op, LHS: lhs, RHS: rhs}
}
func and(lhs, rhs ast.Expr) *ast.BinaryExpr { return bin(lexer.And, lhs, rhs) }
func or(lhs, rhs ast.Expr) *ast.BinaryExpr  { return bin(lexer.Or, lhs, rhs) }

func evtName(op lexer.Token, rhs ast.Expr) *ast.BinaryExpr {
	return bin(op, field(fields.EvtName), rhs)
}

func evtEq(name string) *ast.BinaryExpr { return evtName(lexer.Eq, str(name)) }

func otherEq() *ast.BinaryExpr { return bin(lexer.Eq, field(psName), str("cmd.exe")) }

func TestNewScope(t *testing.T) {
	ts := newTypes(t)

	tests := []struct {
		name string
		expr ast.Expr
		want Scope
	}{
		{"nil expression", nil, nil},

		// equality and membership
		{"eq", evtEq(ts.an), Scope{ts.a}},
		{"eq with swapped operands", bin(lexer.Eq, str(ts.an), field(fields.EvtName)), Scope{ts.a}},
		{"in", evtName(lexer.In, list(ts.an, ts.bn)), Scope{ts.a, ts.b}},
		{"in is sorted and deduplicated", evtName(lexer.In, list(ts.bn, ts.an, ts.bn)), Scope{ts.a, ts.b}},
		{"in with a single value", evtName(lexer.In, list(ts.cn)), Scope{ts.c}},

		// case sensitivity follows the runtime semantics of the operators
		{"ieq ignores case", evtName(lexer.IEq, str(strings.ToUpper(ts.an))), Scope{ts.a}},
		{"ieq with swapped operands", bin(lexer.IEq, str(strings.ToUpper(ts.an)), field(fields.EvtName)), Scope{ts.a}},
		{"iin ignores case", evtName(lexer.IIn, list(strings.ToUpper(ts.an), ts.bn)), Scope{ts.a, ts.b}},
		{"eq is case sensitive", evtEq(strings.ToUpper(ts.an)), nil},
		{"in is case sensitive", evtName(lexer.In, list(ts.an, strings.ToUpper(ts.bn))), nil},

		// names that can't be resolved leave the scope unbounded
		{"unknown name", evtEq("NoSuchEvent"), nil},
		{"unknown name among known ones", evtName(lexer.In, list(ts.an, "NoSuchEvent")), nil},
		{"ieq unknown name", evtName(lexer.IEq, str("NoSuchEvent")), nil},
		{"empty list", evtName(lexer.In, list()), nil},

		// shapes and operators that can't be reasoned about
		{"neq", evtName(lexer.Neq, str(ts.an)), nil},
		{"contains", evtName(lexer.Contains, str(ts.an)), nil},
		{"startswith", evtName(lexer.Startswith, str(ts.an)), nil},
		{"in can't swap operands", bin(lexer.In, list(ts.an), field(fields.EvtName)), nil},
		{"other field", otherEq(), nil},
		{"field compared to evt.name", bin(lexer.Eq, field(psName), field(fields.EvtName)), nil},
		{"evt.name compared to field", bin(lexer.Eq, field(fields.EvtName), field(psName)), nil},
		{"evt.name compared to evt.name", bin(lexer.Eq, field(fields.EvtName), field(fields.EvtName)), nil},
		{"string literal on both sides", bin(lexer.Eq, str(ts.an), str(ts.an)), nil},

		// and: intersection, unconstrained sides ignored
		{"and with unconstrained side", and(evtEq(ts.an), otherEq()), Scope{ts.a}},
		{"and with unconstrained side first", and(otherEq(), evtEq(ts.an)), Scope{ts.a}},
		{"and of two unconstrained sides", and(otherEq(), otherEq()), nil},
		{"and intersects", and(evtName(lexer.In, list(ts.an, ts.bn)), evtName(lexer.In, list(ts.bn, ts.cn))), Scope{ts.b}},
		{"and of equal scopes", and(evtEq(ts.an), evtEq(ts.an)), Scope{ts.a}},
		// a conjunction that can't match anything is reported as unbounded,
		// which over-approximates but never excludes a matching event
		{"and of disjoint scopes", and(evtEq(ts.an), evtEq(ts.bn)), nil},
		{"and with negation", and(evtEq(ts.an), not(otherEq())), Scope{ts.a}},

		// or: union, unconstrained if either side is
		{"or unions", or(evtEq(ts.an), evtEq(ts.bn)), Scope{ts.a, ts.b}},
		{"or deduplicates", or(evtEq(ts.bn), evtName(lexer.In, list(ts.an, ts.bn))), Scope{ts.a, ts.b}},
		{"or with unconstrained side", or(evtEq(ts.an), otherEq()), nil},
		{"or with unconstrained side first", or(otherEq(), evtEq(ts.an)), nil},
		{"or with a contradiction", or(evtEq(ts.cn), and(evtEq(ts.an), evtEq(ts.bn))), nil},

		// not
		{"not", not(evtEq(ts.an)), nil},
		{"not around a conjunction", not(and(evtEq(ts.an), otherEq())), nil},

		// parentheses
		{"parenthesized eq", paren(evtEq(ts.an)), Scope{ts.a}},
		{"parenthesized unconstrained", paren(otherEq()), nil},
		{
			"parenthesized or inside and",
			and(paren(or(evtEq(ts.an), evtEq(ts.bn))), otherEq()),
			Scope{ts.a, ts.b},
		},
		{
			"and of parenthesized scopes",
			and(paren(evtName(lexer.In, list(ts.an, ts.bn, ts.cn))), paren(or(evtEq(ts.bn), evtEq(ts.cn)))),
			Scope{ts.b, ts.c},
		},
		{
			"or of parenthesized conjunctions",
			or(paren(and(evtEq(ts.an), otherEq())), paren(and(evtEq(ts.bn), otherEq()))),
			Scope{ts.a, ts.b},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewScope(tt.expr)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want == nil, got.IsUnbounded())
		})
	}
}
