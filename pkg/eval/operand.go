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
	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
)

// ConstEvaluator is the evaluator of a literal. It has the same value for
// every event.
type ConstEvaluator struct {
	EvaluatorBase
	Value any
}

func (c *ConstEvaluator) Eval(*EvalCtx) any { return c.Value }

// valueEvaluator reads a value that isn't extracted from the evaluated
// event: the field of an event matched by the preceding sequence step, or
// the variable bound by the foreach function. The value is found in the
// context under the variable as it is written in the expression.
type valueEvaluator struct {
	EvaluatorBase
	key string
}

func (v *valueEvaluator) Eval(ctx *EvalCtx) any {
	return ctx.Values[v.key]
}

// fieldOperand reads the field of the evaluated event. The field is extracted
// the first time it is asked for, and every other reference to it in any of the
// expressions evaluated against the event reads the value from the context.
type fieldOperand struct {
	EvaluatorBase
	field *boundField
	x     *extractor
}

func (f *fieldOperand) Eval(ctx *EvalCtx) any {
	ctx.put(f.field, f.x)
	return ctx.Values[f.field.key]
}

// compileOperand compiles the expression that is not a logical or a comparison
// operator: a literal, a field or a function call.
func compileOperand(expr ast.Expr, x *extractor) Evaluator {
	switch expr := expr.(type) {
	case *ast.ParenExpr:
		return compileNode(expr.Expr, x)
	case *ast.IntegerLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.UnsignedLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.DecimalLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.StringLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.ListLiteral:
		return &ConstEvaluator{Value: expr.Values}
	case *ast.BoolLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.IPLiteral:
		return &ConstEvaluator{Value: expr.Value}
	case *ast.FieldLiteral:
		if f := x.byKey(expr.String()); f != nil {
			return &fieldOperand{field: f, x: x}
		}
		return &valueEvaluator{key: expr.String()}
	case *ast.BoundFieldLiteral:
		return &valueEvaluator{key: expr.Value}
	case *ast.BoundSegmentLiteral:
		return &valueEvaluator{key: expr.Value}
	case *ast.BareBoundVariableLiteral:
		return &valueEvaluator{key: expr.Value}
	case *ast.Function:
		return compileFunction(expr, x)
	}
	// the expressions nothing can be evaluated for have no value
	return &ConstEvaluator{}
}
