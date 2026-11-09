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
// Package macro implements the macro store and the macro expansion pass.
//
// The parser classifies identifiers (fields, functions, macro references) but
// never expands macros. Expansion is a dedicated rewrite pass over the AST,
// similar to how the C preprocessor, Scheme macro expanders or SQL view
// inlining are separate phases. This has a few benefits over expanding macros
// while parsing:
//
//   - macro bodies are parsed once, when the store is built, and not on every
//     use site
//   - cycles are detected with an "in progress" stack instead of blowing up
//     the call stack
//   - parsing remains context-free, so a rule or macro syntax error is
//     reported for the text the user actually wrote
package macro

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/compiler/parser"
	"github.com/rabbitstack/fibratus/pkg/policy"
)

// maxDepth limits how deep macros can reference other macros.
const maxDepth = 32

// Store is the immutable store of macros. All macro bodies are parsed and
// expanded when the store is created, so any syntax error, unknown macro or
// reference cycle is reported up front, even for macros that no rule uses.
// Expanded macro bodies are shared by all expressions that reference the
// macro, which is why AST nodes must be treated as read-only once built.
type Store struct {
	defs     map[policy.MacroID]*policy.MacroDef
	order    []policy.MacroID
	raw      map[policy.MacroID]ast.Expr
	expanded map[policy.MacroID]ast.Expr
}

// NewStore builds the store from macro definitions.
func NewStore(macros ...*policy.MacroDef) (*Store, error) {
	s := &Store{
		defs:     make(map[policy.MacroID]*policy.MacroDef, len(macros)),
		raw:      make(map[policy.MacroID]ast.Expr, len(macros)),
		expanded: make(map[policy.MacroID]ast.Expr, len(macros)),
	}

	for _, m := range macros {
		if err := m.Validate(); err != nil {
			return nil, err
		}
		if _, ok := s.defs[m.ID]; ok {
			return nil, fmt.Errorf("duplicate macro %q", m.ID)
		}
		s.defs[m.ID] = m
		s.order = append(s.order, m.ID)
	}

	// parse macro bodies once. All macro names are known at this point,
	// so macros can reference each other regardless of declaration order
	for _, id := range s.order {
		def := s.defs[id]
		if def.IsList() {
			continue
		}
		expr, err := parser.Parse(def.Expression, parser.WithMacroResolver(s))
		if err != nil {
			return nil, fmt.Errorf("syntax error in %q macro: %w", id, err)
		}
		s.raw[id] = expr
	}

	// expand every macro, so errors are reported even for unused macros
	for _, id := range s.order {
		if s.defs[id].IsList() {
			continue
		}
		if _, err := s.expandMacro(id, nil); err != nil {
			return nil, fmt.Errorf("macro %q: %w", id, err)
		}
	}

	return s, nil
}

// IsMacro determines if there is a macro with the given name.
func (s *Store) IsMacro(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.defs[name]
	return ok
}

// IsListMacro determines if the macro with the given name expands to a list.
func (s *Store) IsListMacro(name string) bool {
	if s == nil {
		return false
	}
	def, ok := s.defs[name]
	return ok && def.IsList()
}

// Get returns the macro by its identifier.
func (s *Store) Get(id policy.MacroID) *policy.MacroDef {
	if s == nil {
		return nil
	}
	return s.defs[id]
}

// Contains returns true if there is a macro with this identifier in the store.
func (s *Store) Contains(id policy.MacroID) bool { return s.Get(id) != nil }

// List returns the macros in the order they were declared.
func (s *Store) List() []*policy.MacroDef {
	if s == nil {
		return nil
	}
	macros := make([]*policy.MacroDef, 0, len(s.order))
	for _, id := range s.order {
		macros = append(macros, s.defs[id])
	}
	return macros
}

// Len returns the number of macros in the store.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.defs)
}

// Expand rewrites all macro references in the expression to macro bodies.
// The given tree is modified in place, so the expression has to be owned
// by the caller. The returned expression replaces the argument, since the
// root can itself be a macro reference.
func (s *Store) Expand(expr ast.Expr) (ast.Expr, error) {
	return s.expand(expr, false, nil)
}

// expand rewrites the node. The listOK flag is set when the node sits
// where a list is acceptable, which is the right operand of comparison
// operators, and the stack tracks macros that are currently being expanded.
func (s *Store) expand(n ast.Expr, listOK bool, stack []policy.MacroID) (ast.Expr, error) {
	switch n := n.(type) {
	case *ast.MacroRef:
		return s.resolve(n, listOK, stack)
	case *ast.BinaryExpr:
		lhs, err := s.expand(n.LHS, false, stack)
		if err != nil {
			return nil, err
		}
		rhs, err := s.expand(n.RHS, n.Op != lexer.And && n.Op != lexer.Or, stack)
		if err != nil {
			return nil, err
		}
		n.LHS, n.RHS = lhs, rhs
	case *ast.NotExpr:
		e, err := s.expand(n.Expr, false, stack)
		if err != nil {
			return nil, err
		}
		n.Expr = e
	case *ast.ParenExpr:
		e, err := s.expand(n.Expr, false, stack)
		if err != nil {
			return nil, err
		}
		n.Expr = e
	case *ast.Function:
		for i, arg := range n.Args {
			e, err := s.expand(arg, false, stack)
			if err != nil {
				return nil, err
			}
			n.Args[i] = e
		}
	case *ast.SequenceExpr:
		for i := range n.Steps {
			e, err := s.expand(n.Steps[i].Expr, false, stack)
			if err != nil {
				return nil, err
			}
			n.Steps[i].Expr = e
		}
	}
	return n, nil
}

func (s *Store) resolve(ref *ast.MacroRef, listOK bool, stack []policy.MacroID) (ast.Expr, error) {
	def := s.Get(ref.Name)
	if def == nil {
		return nil, fmt.Errorf("unknown macro %q", ref.Name)
	}

	if def.IsList() {
		if !listOK {
			return nil, fmt.Errorf("list macro %q can only be used as the right operand of a comparison operator", ref.Name)
		}
		// every use site gets its own copy of the values
		return &ast.ListLiteral{Values: slices.Clone(def.Values)}, nil
	}

	return s.expandMacro(ref.Name, stack)
}

// expandMacro returns the expanded body of the expression macro. The
// result is computed once and reused by every reference to the macro.
func (s *Store) expandMacro(id policy.MacroID, stack []policy.MacroID) (ast.Expr, error) {
	if e, ok := s.expanded[id]; ok {
		return e, nil
	}
	if slices.Contains(stack, id) {
		return nil, fmt.Errorf("macro cycle detected: %s", strings.Join(append(slices.Clone(stack), id), " -> "))
	}
	if len(stack) >= maxDepth {
		return nil, fmt.Errorf("macro %q exceeds the maximum expansion depth of %d", id, maxDepth)
	}

	e, err := s.expand(s.raw[id], false, append(slices.Clone(stack), id))
	if err != nil {
		return nil, err
	}
	s.expanded[id] = e
	return e, nil
}
