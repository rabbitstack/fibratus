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

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
)

// IsExpensive reports whether reading the field is costly: it parses a PE,
// verifies a signature, walks a callstack, queries the file metadata store or
// resolves addresses with the reverse DNS cache. The flag is informative. It
// never changes how an expression is evaluated, which is decided by the order
// the operands are written in. It is only used to warn about the rules that
// pay for such a field before they check something cheap.
func IsExpensive(f fields.Field) bool {
	switch f {
	case fields.FileIsDLL, fields.FileIsDriver, fields.FileIsExecutable,
		fields.NetSIPNames, fields.NetDIPNames:
		return true
	}
	s := string(f)
	return f.Source() == fields.SourcePE ||
		strings.Contains(s, ".signature.") ||
		strings.Contains(s, ".callstack.") ||
		f.IsImageCert() ||
		isModuleFileMeta(f)
}

// isModuleFileMeta reports if the module field reads the file metadata store.
func isModuleFileMeta(f fields.Field) bool {
	switch f {
	case fields.ImageIsDLL, fields.ImageIsDriver, fields.ImageIsExecutable, fields.ImageIsDotnet,
		fields.ModuleIsDLL, fields.ModuleIsDriver, fields.ModuleIsExecutable, fields.ModuleIsDotnet,
		fields.DllIsDotnet:
		return true
	}
	return false
}

// OrderWarning reports an expensive field that is read before a cheap one
// in the same chain of the logical operator. The operands are evaluated in
// written order, so swapping them lets the cheap operand reject the event
// before the expensive one is reached.
type OrderWarning struct {
	Expensive fields.Field
	Cheap     fields.Field
}

// ExpensiveBeforeCheap lists the places where an operand that reads an
// expensive field precedes an operand that reads only cheap fields, in a
// chain of AND or OR operators.
func (e *Program) ExpensiveBeforeCheap() []OrderWarning {
	var ws []OrderWarning
	lintOrder(e.expr, IsExpensive, func(w OrderWarning) { ws = append(ws, w) })
	return ws
}

// lintOrder walks the expression and calls report for every expensive operand
// that has a cheap one after it in the same chain.
func lintOrder(expr ast.Expr, expensive func(fields.Field) bool, report func(OrderWarning)) {
	switch expr := expr.(type) {
	case *ast.SequenceExpr:
		for _, step := range expr.Steps {
			lintOrder(step.Expr, expensive, report)
		}
	case *ast.ParenExpr:
		lintOrder(expr.Expr, expensive, report)
	case *ast.NotExpr:
		lintOrder(expr.Expr, expensive, report)
	case *ast.BinaryExpr:
		if expr.Op != lexer.And && expr.Op != lexer.Or {
			return
		}
		operands := chain(expr, expr.Op, nil)
		for _, op := range operands {
			lintOrder(op, expensive, report)
		}
		for i, op := range operands {
			ef, ok := firstExpensive(op, expensive)
			if !ok {
				continue
			}
			for _, later := range operands[i+1:] {
				if cf, ok := onlyCheap(later, expensive); ok {
					report(OrderWarning{Expensive: ef, Cheap: cf})
					break
				}
			}
		}
	}
}

// chain flattens the nested expressions of the same operator in written order.
func chain(expr ast.Expr, op lexer.Token, operands []ast.Expr) []ast.Expr {
	if b, ok := expr.(*ast.BinaryExpr); ok && b.Op == op {
		return chain(b.RHS, op, chain(b.LHS, op, operands))
	}
	return append(operands, expr)
}

func operandFields(expr ast.Expr) []fields.Field {
	var flds []fields.Field
	ast.WalkFunc(expr, func(n ast.Node) {
		if f, ok := n.(*ast.FieldLiteral); ok {
			flds = append(flds, f.Field)
		}
	})
	return flds
}

func firstExpensive(expr ast.Expr, expensive func(fields.Field) bool) (fields.Field, bool) {
	for _, f := range operandFields(expr) {
		if expensive(f) {
			return f, true
		}
	}
	return "", false
}

// onlyCheap reports if the operand reads at least one field, and
// none of them is expensive. It returns the first field of the operand.
func onlyCheap(expr ast.Expr, expensive func(fields.Field) bool) (fields.Field, bool) {
	flds := operandFields(expr)
	if len(flds) == 0 {
		return "", false
	}
	for _, f := range flds {
		if expensive(f) {
			return "", false
		}
	}
	return flds[0], true
}
