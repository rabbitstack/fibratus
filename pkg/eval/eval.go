/*
 * Copyright 2021-present by Nedim Sabic Sabic
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
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/parser"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/util/sets"
)

type Evaluator struct {
	ID string

	expr ast.Expr

	fields   sets.Set[Field]
	segments sets.Set[Segment]

	accessors []Accessor

	opts ast.EvalOptions
}

func NewEvaluator(id string, expression string) (*Evaluator, error) {
	expr, err := parser.Parse(expression)
	if err != nil {
		return nil, err
	}

	evaluator := &Evaluator{
		ID:        id,
		expr:      expr,
		fields:    sets.New[Field](),
		segments:  sets.New[Segment](),
		accessors: make([]Accessor, 0),
	}

	switch expr := expr.(type) {
	case *ast.BinaryExpr:
		ast.WalkFunc(expr, evaluator.walkFn)
	case *ast.SequenceExpr:
		if expr.By != nil {
			evaluator.addField(expr.By.Fields...)
		}

		for _, step := range expr.Steps {
			ast.WalkFunc(step.Expr, evaluator.walkFn)
			if step.By != nil {
				evaluator.addField(step.By.Fields...)
			}
		}
	}

	return evaluator, nil
}

func (e *Evaluator) Eval(evt *event.Event, valuer *ValuerCache) bool {
	for field := range e.fields {
		valuer.populateValuer(field, evt)
	}
	return ast.Eval(e.expr, valuer.Valuer, e.opts)
}

func (e *Evaluator) EvalExpr(expr ast.Expr, evt *event.Event, valuer *ValuerCache) bool {
	for field := range e.fields {
		valuer.populateValuer(field, evt)
	}
	return ast.Eval(expr, valuer.Valuer, e.opts)
}

func (e *Evaluator) IsSequenceExpr() (isSequence bool) {
	_, isSequence = e.expr.(*ast.SequenceExpr)
	return
}

func (e *Evaluator) GetExpr() ast.Expr {
	return e.expr
}

func (e *Evaluator) GetFields() []Field {
	return e.fields.Values()
}

func (e *Evaluator) GetEventTypes() ([]*event.Type, error) {
	var eventTypes []*event.Type
	ast.WalkFunc(e.expr, func(n ast.Node) {

	})
	return eventTypes, nil
}

func (e *Evaluator) GetDepth() int {
	expr, ok := e.expr.(*ast.SequenceExpr)
	if !ok {
		return 0
	}
	return len(expr.Steps)
}

func (e *Evaluator) GetMaxSpan() time.Duration {
	expr, ok := e.expr.(*ast.SequenceExpr)
	if !ok {
		return 0
	}
	return expr.MaxSpan
}

// GetLink returns the join link for sequence expressions. If
// the expression is not a sequence, this method returns nil.
func (e *Evaluator) GetLink(stepIndex int) *ast.SequenceLink {
	expr, ok := e.expr.(*ast.SequenceExpr)
	if !ok {
		return nil
	}
	if expr.By != nil {
		return expr.By
	}
	return expr.Steps[stepIndex].By
}

func (e *Evaluator) addField(fields ...*ast.FieldLiteral) {
	for _, f := range fields {
		e.fields.Add(Field{Name: f.Field, Value: f.Value, Arg: f.Arg})
	}
}

func (e *Evaluator) addBoundField(fields ...*ast.BoundFieldLiteral) {
	for _, f := range fields {
		e.fields.Add(Field{Name: f.Field.Field, Value: f.Value, Arg: f.Field.Arg, BoundVar: f.BoundVar.Value})
	}
}

func (e *Evaluator) walkFn(n ast.Node) {
	switch expr := n.(type) {
	case *ast.BinaryExpr:
		switch lhs := expr.LHS.(type) {
		case *ast.FieldLiteral:
			e.addField(lhs)
		case *ast.BoundFieldLiteral:
			e.addBoundField(lhs)
		}
		switch rhs := expr.RHS.(type) {
		case *ast.FieldLiteral:
			e.addField(rhs)
		case *ast.BoundFieldLiteral:
			e.addBoundField(rhs)
		}
	case *ast.Function:
		e.opts.MultiValuer = true
		for _, arg := range expr.Args {
			if f, ok := arg.(*ast.FieldLiteral); ok {
				e.fields.Add(Field{f.Field, f.Value, f.Arg, ""})
			}
			if f, ok := arg.(*ast.BoundFieldLiteral); ok {
				e.fields.Add(Field{f.Field.Field, f.Value, f.Field.Arg, f.BoundVar.Value})
			}
			// switch exp := arg.(type) {
			// case *ast.BinaryExpr:
			// 	// if segment, ok := exp.LHS.(*ql.BoundSegmentLiteral); ok {
			// 	// 	f.addSegment(segment)
			// 	// }
			// 	// if segment, ok := exp.RHS.(*ql.BoundSegmentLiteral); ok {
			// 	// 	f.addSegment(segment)
			// 	// }
			// }
		}
	case *ast.FieldLiteral:
		// if fields.IsBoolean(expr.Field) {
		// 	//f.addField(expr)
		// }
	}
}
