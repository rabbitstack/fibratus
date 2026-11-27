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
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
)

// Predicate reports whether the event of the evaluation context
// satisfies a compiled expression.
type Predicate interface {
	Eval(*EvalCtx) bool
}

// tree is the root of the compiled expression. Every node of the tree is an
// Evaluator that produces a value: a bool, or nil if the expression is
// undefined, e.g. a comparison between incomparable types. The tree has to keep
// the undefined value around, since the nodes above treat it differently from
// false: a nil operand is cast to false only when the other operand is a bool,
// and negating it leaves it undefined.
type tree struct {
	root Evaluator
}

// Eval collapses the undefined value to false.
func (t *tree) Eval(ctx *EvalCtx) bool {
	b, ok := t.root.Eval(ctx).(bool)
	return ok && b
}

// compile builds the tree of the expression. The logical operators and the
// negation become nodes, the comparison operators become comparison evaluators,
// and the literals and the fields are the operands. The AST of a sequence step
// is compiled the same way, since each step is an ordinary expression.
func compile(expr ast.Expr, x *extractor) Predicate {
	return &tree{root: compileNode(expr, x)}
}

func compileNode(expr ast.Expr, x *extractor) Evaluator {
	switch expr := expr.(type) {
	case *ast.ParenExpr:
		return compileNode(expr.Expr, x)
	case *ast.BinaryExpr:
		lhs, rhs := compileNode(expr.LHS, x), compileNode(expr.RHS, x)
		switch expr.Op {
		case lexer.And:
			return &andNode{lhs: lhs, rhs: rhs}
		case lexer.Or:
			return &orNode{lhs: lhs, rhs: rhs}
		}
		return &Comparison{Op: expr.Op, LHS: lhs, RHS: rhs}
	case *ast.NotExpr:
		return compileNot(expr, x)
	}
	return compileOperand(expr, x)
}

// compileNot compiles the negation. Only the operands below can be negated, and
// each of them has its own rules. The negation of any other expression is undefined.
func compileNot(expr *ast.NotExpr, x *extractor) Evaluator {
	switch operand := expr.Expr.(type) {
	case *ast.BinaryExpr:
		return &notNode{operand: compileNode(operand, x)}
	case *ast.ParenExpr:
		return &notNode{operand: compileNode(operand.Expr, x)}
	case *ast.Function:
		return &notCallNode{call: compileOperand(operand, x)}
	case *ast.BoolLiteral:
		return &ConstEvaluator{Value: !operand.Value}
	}
	return &ConstEvaluator{}
}

// andNode is the AND operator. The right operand is reached only if the left
// one doesn't settle the result, so the fields it reads are extracted only then.
type andNode struct {
	EvaluatorBase
	lhs, rhs Evaluator
}

func (n *andNode) Eval(ctx *EvalCtx) any {
	l := n.lhs.Eval(ctx)
	if b, ok := l.(bool); ok && !b {
		return false
	}
	return logical(l, n.rhs, ctx, func(l, r bool) bool { return l && r })
}

// orNode is the OR operator.
type orNode struct {
	EvaluatorBase
	lhs, rhs Evaluator
}

func (n *orNode) Eval(ctx *EvalCtx) any {
	l := n.lhs.Eval(ctx)
	if b, ok := l.(bool); ok && b {
		return true
	}
	return logical(l, n.rhs, ctx, func(l, r bool) bool { return l || r })
}

// logical finishes AND/OR once the left operand didn't settle the result.
// An undefined left operand is cast to false when the right one is a bool, and
// the result is undefined otherwise. If the left operand is a bool, the result
// is false when the right one isn't, which covers the undefined right operand
// that is cast to false. The result is undefined if the left operand isn't a
// bool, so the right operand doesn't have to be evaluated.
func logical(l any, rhs Evaluator, ctx *EvalCtx, op func(l, r bool) bool) any {
	if l != nil {
		if _, ok := l.(bool); !ok {
			return nil
		}
	}
	r := rhs.Eval(ctx)
	if l == nil {
		if _, ok := r.(bool); !ok {
			return nil
		}
		l = false
	}
	rb, ok := r.(bool)
	return ok && op(l.(bool), rb)
}

// notNode negates the logical operand. An undefined operand stays undefined.
type notNode struct {
	EvaluatorBase
	operand Evaluator
}

func (n *notNode) Eval(ctx *EvalCtx) any {
	v, ok := n.operand.Eval(ctx).(bool)
	if !ok {
		return nil
	}
	return !v
}

// notCallNode negates the function call. A call that has no value is
// negated to true, and the one that returns something else than a bool is
// undefined.
type notCallNode struct {
	EvaluatorBase
	call Evaluator
}

func (n *notCallNode) Eval(ctx *EvalCtx) any {
	switch v := n.call.Eval(ctx).(type) {
	case nil:
		return true
	case bool:
		return !v
	}
	return nil
}

// Comparison is the evaluator of the binary operators that compare the operands,
// e.g. =, >=, contains or imatches. The operands are evaluators themselves: the
// fields, the literals and the function calls. The undefined value of an operand
// is cast to false if the other operand is a bool, and how the values of the
// operands are compared is up to the type of the left one.
type Comparison struct {
	EvaluatorBase
	Op       lexer.Token
	LHS, RHS Evaluator
}

func (c *Comparison) Eval(ctx *EvalCtx) any {
	l, r := c.LHS.Eval(ctx), c.RHS.Eval(ctx)
	switch {
	case l == nil && r != nil:
		if _, ok := r.(bool); ok {
			l = false
		}
	case l != nil && r == nil:
		if _, ok := l.(bool); ok {
			r = false
		}
	}
	return compare(c.Op, l, r)
}
