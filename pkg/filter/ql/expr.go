/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package ql

import (
	"strings"
)

// Node represents a node in the abstract syntax tree.
type Node interface {
	String() string
}

// Expr represents an expression that can be evaluated to a value.
type Expr interface {
	Node
}

// ParenExpr represents a parenthesized expression.
type ParenExpr struct {
	Expr Expr
}

// String returns a string representation of the parenthesized expression.
func (e *ParenExpr) String() string {
	var b strings.Builder
	b.Grow(len(e.Expr.String()) + 2)
	b.WriteRune('(')
	b.WriteString(e.Expr.String())
	b.WriteRune(')')
	return b.String()
}

// BinaryExpr represents an operation between two expressions.
type BinaryExpr struct {
	Op  token
	LHS Expr
	RHS Expr
}

// String returns a string representation of the binary expression.
func (e *BinaryExpr) String() string {
	var b strings.Builder

	lhs := e.LHS.String()
	op := e.Op.String()
	rhs := e.RHS.String()

	b.Grow(len(lhs) + len(op) + len(rhs) + 2)

	b.WriteString(lhs)
	b.WriteString(" ")
	b.WriteString(op)
	b.WriteString(" ")
	b.WriteString(rhs)

	return b.String()
}

// NotExpr represents an unary not expression.
type NotExpr struct {
	Expr Expr
}

// String returns a string representation of the not expression.
func (e *NotExpr) String() string {
	var b strings.Builder
	b.Grow(len(e.Expr.String()) + 4)
	b.WriteString("NOT ")
	b.WriteString(e.Expr.String())
	return b.String()
}
