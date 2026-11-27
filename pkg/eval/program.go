/*
 * Copyright 2021-2026 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/macro"
	"github.com/rabbitstack/fibratus/pkg/compiler/parser"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// Program evaluates a rule expression against events.
//
// A Program is immutable once constructed, so it is safe for concurrent
// use as long as each goroutine brings its own EvalCtx and the evaluators
// are themselves safe for concurrent use.
type Program struct {
	// ID identifies the evaluator, typically the rule or filter name.
	ID string

	expr ast.Expr

	fields Fields
	// boundFields are the fields referenced through the bound variables
	// of a sequence, e.g. $e1.ps.name. Their values are extracted from the
	// events of the previous steps, never from the evaluated event.
	boundFields Fields
	segments    Segments

	evalOpts options

	// scope is the set of event types the expression can possibly match.
	scope Scope

	// extractor reads the field values from events through the typed
	// evaluators of the fields of the expression.
	extractor *extractor

	// trees are the compiled expressions: the one of the expression itself,
	// or one for each step of a sequence, keyed by the step expression.
	trees map[ast.Expr]Predicate
}

// Option configures the evaluator.
type Option func(*options)

type options struct {
	resolvers *Resolvers
	macros    *macro.Store
	scopeEval bool
}

// WithMacros makes the macros from the store available to the expression.
// The macro references are expanded right after parsing.
func WithMacros(macros *macro.Store) Option {
	return func(o *options) { o.macros = macros }
}

// WithResolvers replaces the resolvers of the expensive values, the signature
// store, the file metadata store and the reverse DNS among them, so a test can
// count the calls or avoid the real stores.
func WithResolvers(r *Resolvers) Option {
	return func(o *options) { o.resolvers = r }
}

// WithEventScopeEval short-circuits the evaluation to false for events whose
// type is outside the scope of the expression, skipping field extraction.
func WithEventScopeEval() Option {
	return func(o *options) { o.scopeEval = true }
}

// NewProgram parses the expression, expands the macros if the macro
// store is given, and collects the fields used by the expression.
func NewProgram(id string, expression string, opts ...Option) (*Program, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	var err error
	var expr ast.Expr
	if o.macros != nil {
		expr, err = parser.Parse(expression, parser.WithMacroResolver(o.macros))
		if err != nil {
			return nil, err
		}
		expr, err = o.macros.Expand(expr)
	} else {
		expr, err = parser.Parse(expression)
	}
	if err != nil {
		return nil, err
	}

	e := &Program{
		ID:       id,
		evalOpts: o,
		expr:     expr,
		scope:    NewScope(expr),
	}

	ast.WalkFunc(expr, e.visit)

	e.extractor = newExtractor(e.fields, e.boundFields, e.segments)
	if o.resolvers != nil {
		e.extractor.resolvers = o.resolvers
	}
	e.trees = e.compileTrees()

	return e, nil
}

// Eval reports whether the event satisfies the expression.
func (e *Program) Eval(evt *event.Event, valuer *EvalCtx) bool {
	return e.eval(e.expr, evt, valuer)
}

// EvalExpr evaluates an arbitrary expression, e.g. a single sequence step,
// using the fields and the scope collected by this evaluator.
func (e *Program) EvalExpr(expr ast.Expr, evt *event.Event, valuer *EvalCtx) bool {
	return e.eval(expr, evt, valuer)
}

// Extract extracts the values of all the fields referenced by the expression
// from the event into the valuer, so they can be used before the evaluation.
func (e *Program) Extract(evt *event.Event, valuer *EvalCtx) {
	e.extractor.extractAll(evt, valuer)
}

// ExtractLink extracts the fields of the sequence link from the event into
// the valuer. The tree extracts a field only when it reaches it, but the
// link is read by the sequence evaluator no matter what the step expression
// evaluates to, so the sequence evaluator asks for the link explicitly.
func (e *Program) ExtractLink(link *ast.SequenceLink, evt *event.Event, valuer *EvalCtx) {
	if link == nil {
		return
	}
	valuer.Evt = evt
	for _, lf := range link.Fields {
		if f := e.extractor.byKey(lf.String()); f != nil {
			valuer.put(f, e.extractor)
		}
	}
}

// Extract extracts the value of the specified field referenced by the expression
// from the event and returns its value without caching inside the valuer.
func (e *Program) ExtractField(f Field, evt *event.Event) any {
	return e.extractor.Extract(f, evt)
}

func (e *Program) eval(expr ast.Expr, evt *event.Event, valuer *EvalCtx) bool {
	if e.evalOpts.scopeEval && !e.scope.Contains(evt.Type) {
		return false
	}
	t := e.trees[expr]
	if t == nil {
		// not an expression the program was compiled from
		t = compile(expr, e.extractor)
	}
	valuer.Evt = evt
	return t.Eval(valuer)
}

func (e *Program) IsSequenceExpr() (isSequence bool) {
	_, isSequence = e.expr.(*ast.SequenceExpr)
	return
}

func (e *Program) GetExpr() ast.Expr {
	return e.expr
}

func (e *Program) GetScope() Scope {
	return e.scope
}

// GetEventTypes returns all event types reachable in the expression.
// Alias for event scopes.
func (e *Program) GetEventTypes() []event.Type {
	return e.scope
}

// GetFields returns the unique fields referenced by the expression.
func (e *Program) GetFields() []Field {
	return e.fields
}

// GetBoundFields returns the unique fields the expression references
// through the bound variables of the sequence steps.
func (e *Program) GetBoundFields() []Field {
	return e.boundFields
}

// visit records the fields and segments the expression refers to, so they
// can be extracted from the event before the evaluation. It is meant to be
// called for every node of the expression through ast.WalkFunc.
func (e *Program) visit(n ast.Node) {
	switch n := n.(type) {
	case *ast.FieldLiteral:
		e.fields.Add(n.Field, n.Value, n.Arg)
	case *ast.BoundFieldLiteral:
		// Walk doesn't descend into the bound literal, so the inner field
		// has to be recorded here. Otherwise, a bound field such as
		// $e1.ps.pe.imphash would never tell which PE directories to parse
		if n.Field != nil {
			e.boundFields.Add(n.Field.Field, n.Field.Value, n.Field.Arg)
		}
	case *ast.BoundSegmentLiteral:
		//e.segments.Add(Segment{BoundVar: n.BoundVar.Value, Name: n.Segment})
	case *ast.SequenceExpr:
		// the `by` fields aren't nodes of the tree, so Walk never reaches them
		if n.By != nil {
			for _, f := range n.By.Fields {
				e.fields.Add(f.Field, f.Value, f.Arg)
			}
		}
		for _, step := range n.Steps {
			if step.By == nil {
				continue
			}
			for _, f := range step.By.Fields {
				e.fields.Add(f.Field, f.Value, f.Arg)
			}
		}
	}
}

// compileTrees compiles the expression of the program, or each step of
// the sequence the expression is made of.
func (e *Program) compileTrees() map[ast.Expr]Predicate {
	trees := make(map[ast.Expr]Predicate)
	if seq, ok := e.expr.(*ast.SequenceExpr); ok {
		for _, step := range seq.Steps {
			trees[step.Expr] = compile(step.Expr, e.extractor)
		}
		return trees
	}
	trees[e.expr] = compile(e.expr, e.extractor)
	return trees
}
