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

// Evaluator evaluates a rule expression against events.
//
// An Evaluator is immutable once constructed, so it is safe for concurrent
// use as long as each goroutine brings its own ValuerCache and the accessors
// are themselves safe for concurrent use.

type Evaluator struct {
	// ID identifies the evaluator, typically the rule or filter name.
	ID string

	expr     ast.Expr
	fields   Fields
	segments Segments

	astOpts  ast.EvalOptions
	evalOpts options

	// scope is the set of event types the expression can possibly match.
	scope Scope

	// extractor reads the field values from events using the accessors
	// tuned to the fields and segments of this expression.
	extractor *Extractor
}

// Option configures the evaluator.
type Option func(*options)

type options struct {
	macros    *macro.Store
	scopeEval bool
}

// WithMacros makes the macros from the store available to the expression.
// The macro references are expanded right after parsing.
func WithMacros(macros *macro.Store) Option {
	return func(o *options) { o.macros = macros }
}

// WithEventScopeEval short-circuits the evaluation to false for events whose
// type is outside the scope of the expression, skipping field extraction.
func WithEventScopeEval() Option {
	return func(o *options) { o.scopeEval = true }
}

// NewEvaluator parses the expression, expands the macros if the macro
// store is given, and collects the fields used by the expression.
func NewEvaluator(id string, expression string, opts ...Option) (*Evaluator, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	var expr ast.Expr
	var err error
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

	e := &Evaluator{
		ID:       id,
		evalOpts: o,
		expr:     expr,
		scope:    NewScope(expr),
		fields:   NewFields(),
	}

	ast.WalkFunc(expr, e.visit)

	// the accessors can only be configured once all fields and segments are known
	//eval.extractor = NewExtractor(eval.fields.List(), eval.segments.List())

	return e, nil
}

// Eval reports whether the event satisfies the expression.
func (e *Evaluator) Eval(evt *event.Event, valuer *ValuerCache) bool {
	return e.eval(e.expr, evt, valuer)
}

// EvalExpr evaluates an arbitrary expression, e.g. a single sequence step,
// using the fields and the scope collected by this evaluator.
func (e *Evaluator) EvalExpr(expr ast.Expr, evt *event.Event, valuer *ValuerCache) bool {
	return e.eval(expr, evt, valuer)
}

// Extract extracts the values of all the fields referenced by the expression
// from the event into the valuer, so they can be used before the evaluation.
func (e *Evaluator) Extract(evt *event.Event, valuer *ValuerCache) {
	e.extractor.ExtractToValuer(evt, valuer)
}

func (e *Evaluator) eval(expr ast.Expr, evt *event.Event, valuer *ValuerCache) bool {
	if e.evalOpts.scopeEval && !e.scope.Contains(evt.Type) {
		return false
	}
	e.extractor.ExtractToValuer(evt, valuer)
	return ast.Eval(expr, valuer.Valuer, e.astOpts)
}

func (e *Evaluator) IsSequenceExpr() (isSequence bool) {
	_, isSequence = e.expr.(*ast.SequenceExpr)
	return
}

func (e *Evaluator) GetExpr() ast.Expr {
	return e.expr
}

func (e *Evaluator) GetEventTypes() []event.Type {
	return e.scope
}

// GetFields returns the unique fields referenced by the expression.
func (e *Evaluator) GetFields() []Field {
	return e.fields.List()
}

// visit records the fields and segments the expression refers to, so they
// can be extracted from the event before the evaluation. It is meant to be
// called for every node of the expression through ast.WalkFunc.
func (e *Evaluator) visit(n ast.Node) {
	switch n := n.(type) {
	case *ast.FieldLiteral:
		e.addField(n)
	case *ast.BoundFieldLiteral:
		e.fields.Add(Field{Name: n.Field.Field, Value: n.Value, Arg: n.Field.Arg, BoundVar: n.BoundVar.Value})
	case *ast.BoundSegmentLiteral:
		//e.segments.Add(Segment{BoundVar: n.BoundVar.Value, Name: n.Segment})
	case *ast.Function:
		e.astOpts.MultiValuer = true
	case *ast.SequenceExpr:
		// the `by` fields aren't nodes of the tree, so Walk never reaches them
		if n.By != nil {
			e.addFields(n.By.Fields...)
		}
		for _, step := range n.Steps {
			if step.By == nil {
				continue
			}
			e.addFields(step.By.Fields...)
		}
	}
}

func (e *Evaluator) addField(f *ast.FieldLiteral) {
	e.fields.Add(Field{Name: f.Field, Value: f.Value, Arg: f.Arg})
}

func (e *Evaluator) addFields(fields ...*ast.FieldLiteral) {
	for _, f := range fields {
		e.addField(f)
	}
}
