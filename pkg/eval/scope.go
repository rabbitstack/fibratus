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
	"slices"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// Scope is the set of event types an expression can possibly match.
// An empty scope means the scope is unbounded: nothing is known about
// which event types the expression can match, so none can be ruled out.
type Scope []event.Type

// NewScope infers the scope of the filter expression.
func NewScope(expr ast.Expr) Scope {
	return scopeOf(expr)
}

// Contains indicates if an event of the given type can match the expression.
// An unbounded scope contains every event type.
func (s Scope) Contains(t event.Type) bool {
	return s.IsUnbounded() || slices.Contains(s, t)
}

// IsUnbounded indicates if the scope can't rule out any event type.
func (s Scope) IsUnbounded() bool {
	return len(s) == 0
}

// scopeOf infers the event types the expression can match by looking at
// `evt.name` comparisons while respecting the boolean structure:
//
//   - a and b: the intersection of both sides, unconstrained sides ignored
//   - a or b:  the union of both sides, unconstrained if either side is
//   - anything else (not, other fields): unconstrained
func scopeOf(expr ast.Expr) Scope {
	var s Scope
	switch expr := expr.(type) {
	case *ast.BinaryExpr:
		switch expr.Op {
		case lexer.And:
			s = intersect(scopeOf(expr.LHS), scopeOf(expr.RHS))
		case lexer.Or:
			s = union(scopeOf(expr.LHS), scopeOf(expr.RHS))
		default:
			s = scopeOfComparison(expr)
		}
	case *ast.SequenceExpr:
		for i := range expr.Steps {
			step := scopeOf(expr.Steps[i].Expr)
			if len(step) == 0 {
				return nil
			}
			if i == 0 {
				s = step
				continue
			}
			s = union(s, step)
		}
	}
	slices.Sort(s)
	return slices.Compact(s)
}

// scopeOfComparison handles `evt.name = 'X'`, `evt.name in ('X', 'Y')` and
// their case-insensitive variants. The operands of (i)equals may be swapped.
func scopeOfComparison(b *ast.BinaryExpr) Scope {
	var operand ast.Expr

	field, ok := b.LHS.(*ast.FieldLiteral)
	if ok {
		operand = b.RHS
	} else if b.Op == lexer.Eq || b.Op == lexer.IEq {
		field, ok = b.RHS.(*ast.FieldLiteral)
		operand = b.LHS
	}
	if !ok || field.Field != fields.EvtName {
		return nil
	}

	switch b.Op {
	case lexer.Eq, lexer.IEq, lexer.In, lexer.IIn:
	default:
		return nil
	}

	values := stringValues(operand)
	if len(values) == 0 {
		return nil
	}
	var s Scope
	for _, name := range values {
		t, ok := event.ParseType(name)
		if !ok {
			// can't tell what the name resolves to at runtime,
			// so don't risk excluding events that might match
			return nil
		}
		s = append(s, t)
	}
	return s
}

// stringValues returns the string constants of a string or list literal.
func stringValues(expr ast.Expr) []string {
	switch v := expr.(type) {
	case *ast.StringLiteral:
		return []string{v.Value}
	case *ast.ListLiteral:
		return v.Values
	}
	return nil
}

// intersect returns the event types present in both scopes. An unbounded side
// constrains nothing, so the other side is returned as is. Disjoint scopes
// can't match anything, but they are reported as unbounded, which is a safe
// over-approximation.
func intersect(a, b Scope) Scope {
	if a.IsUnbounded() {
		return b
	}
	if b.IsUnbounded() {
		return a
	}
	var s Scope
	for _, t := range a {
		if slices.Contains(b, t) {
			s = append(s, t)
		}
	}
	return s
}

// union returns the event types present in either scope. The union is
// unbounded if either side is.
func union(a, b Scope) Scope {
	if a.IsUnbounded() || b.IsUnbounded() {
		return nil
	}
	s := make(Scope, 0, len(a)+len(b))
	s = append(s, a...)
	s = append(s, b...)
	return s
}
