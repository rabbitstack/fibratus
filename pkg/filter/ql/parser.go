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
 *
 *  Copyright (c) 2013-2016 Errplane Inc.
 */

package ql

import (
	"net"
	"strconv"
	"strings"
)

// Parser builds the binary expression tree from the filter string.
type Parser struct {
	s    *bufScanner
	expr string
}

// NewParser builds a new parser instance from the expression string.
func NewParser(expr string) *Parser {
	return &Parser{s: newBufScanner(strings.NewReader(expr)), expr: expr}
}

// ParseExpr parses an expression by building the binary expression tree.
func (p *Parser) ParseExpr() (Expr, error) {
	var err error
	root := &BinaryExpr{}

	// parse a non-binary expression type to start. This variable will always be
	// the root of the expression tree.
	root.RHS, err = p.parseUnaryExpr()
	if err != nil {
		return nil, err
	}

	// loop over operations and unary exprs and build a tree based on precedence.
	for {
		// if the next token is NOT an operator then return the expression.
		op, pos, lit := p.scanIgnoreWhitespace()
		if !op.isOperator() {
			p.unscan()
			if op != eof && op != rparen && op != comma {
				return nil, newParseError(tokstr(op, lit), []string{"operator", "')'", "','"}, pos, p.expr)
			}
			return root.RHS, nil
		}

		var rhs Expr
		if op == not {
			// parse the operator
			op1, pos, lit := p.scanIgnoreWhitespace()
			if !op1.isOperator() {
				return nil, newParseError(tokstr(op, lit), []string{"operator"}, pos, p.expr)
			}
			// parse the next expression after operator
			rhs1, err := p.parseUnaryExpr()
			if err != nil {
				return nil, err
			}
			rhs = &BinaryExpr{RHS: rhs1, Op: op1}
		} else {
			op1, _, _ := p.scanIgnoreWhitespace()
			// if the negation appears after the operator
			// try to parse an entire binary expr and wrap
			// it inside the `not` expression
			if op1 == not {
				binaryExpr, err := p.ParseExpr()
				if err != nil {
					return nil, err
				}
				rhs = &NotExpr{binaryExpr}
			} else {
				p.unscan()
				// otherwise, parse the next expression
				rhs, err = p.parseUnaryExpr()
				if err != nil {
					return nil, err
				}
			}
		}

		// find the right spot in the tree to add the new expression by
		// descending the RHS of the expression tree until we reach the last
		// BinaryExpr or a BinaryExpr whose RHS has an operator with
		// precedence >= the operator being added.
		for node := root; ; {
			r, ok := node.RHS.(*BinaryExpr)
			if !ok || r.Op.precedence() >= op.precedence() {
				if op == not {
					r := rhs.(*BinaryExpr)
					r.LHS = node.RHS
					node.RHS = &NotExpr{Expr: r}
					break
				}
				// Add the new expression here and break.
				node.RHS = &BinaryExpr{LHS: node.RHS, RHS: rhs, Op: op}
				break
			}
			node = r
		}
	}
}

// parseUnaryExpr parses an non-binary expression.
func (p *Parser) parseUnaryExpr() (Expr, error) {
	// If the first token is a LPAREN then parse it as its own grouped expression.
	if tok, _, _ := p.scanIgnoreWhitespace(); tok == lparen {
		// parse a comma-separated list if this looks like a list
		tagKeys, err := p.parseList()
		if err != nil {
			p.unscan()
			// if it fails, try to parse the grouped expression
			expr, err := p.ParseExpr()
			if err != nil {
				return nil, err
			}
			// Expect an RPAREN at the end.
			if tok, pos, lit := p.scanIgnoreWhitespace(); tok != rparen {
				return nil, newParseError(tokstr(tok, lit), []string{"')'"}, pos, p.expr)
			}
			return &ParenExpr{Expr: expr}, nil
		}

		// Expect an RPAREN at the end of list
		if tok, pos, lit := p.scanIgnoreWhitespace(); tok != rparen {
			return nil, newParseError(tokstr(tok, lit), []string{"')'"}, pos, p.expr)
		}

		return &ListLiteral{Values: tagKeys}, nil
	}

	p.unscan()

	tok, pos, lit := p.scanIgnoreWhitespace()
	switch tok {
	case ident:
		if tok0, _, _ := p.scan(); tok0 == lparen {
			return p.parseFunction(lit)
		}
		// unscan lparen and ident tokens
		p.unscan()
		p.unscan()
	case ip:
		return &IPLiteral{Value: net.ParseIP(lit)}, nil
	case str:
		return &StringLiteral{Value: lit}, nil
	case field:
		return &FieldLiteral{Value: lit}, nil
	case patternBinding:
		return &PatternBindingLiteral{Value: lit}, nil
	case truet, falset:
		return &BoolLiteral{Value: tok == truet}, nil
	case integer:
		v, err := strconv.ParseInt(lit, 10, 64)
		if err != nil {
			// The literal may be too large to fit into an int64. If it is, use an unsigned integer.
			// The check for negative numbers is handled somewhere else so this should always be a positive number.
			if v, err := strconv.ParseUint(lit, 10, 64); err == nil {
				return &UnsignedLiteral{Value: v}, nil
			}
			return nil, &ParseError{Message: "unable to parse integer", Pos: pos}
		}
		return &IntegerLiteral{Value: v}, nil
	case dec:
		v, err := strconv.ParseFloat(lit, 64)
		if err != nil {
			return nil, &ParseError{Message: "unable to parse decimal", Pos: pos}
		}
		return &DecimalLiteral{Value: v}, nil
	}

	expectations := []string{"field", "string", "number", "bool", "ip", "function", "pattern binding"}
	if tok == badip {
		expectations = []string{"a valid IP address"}
	}
	if tok == badesc || tok == badstr {
		expectations = []string{"a valid string but bad string or escape found"}
	}

	return nil, newParseError(tokstr(tok, lit), expectations, pos, p.expr)
}

func (p *Parser) parseList() ([]string, error) {
	tok, pos, lit := p.scanIgnoreWhitespace()
	if tok != str && tok != ip && tok != integer {
		return []string{}, newParseError(tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
	}
	idents := []string{lit}

	// parse remaining identifiers
	for {
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != comma {
			p.unscan()
			return idents, nil
		}

		tok, pos, lit := p.scanIgnoreWhitespace()
		if tok != str && tok != ip && tok != integer {
			return []string{}, newParseError(tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
		}

		idents = append(idents, lit)
	}
}

// parseFunction parses a function call. This function assumes
// the function name and LPAREN have been consumed.
func (p *Parser) parseFunction(name string) (*Function, error) {
	name = strings.ToLower(name)
	args := make([]Expr, 0)

	// If there's a right paren then just return immediately.
	// This is the case for functions without arguments
	if tok, _, _ := p.scan(); tok == rparen {
		fn := &Function{Name: name}
		if err := fn.validate(); err != nil {
			return nil, err
		}
		return fn, nil
	}
	p.unscan()

	arg, err := p.ParseExpr()
	if err != nil {
		return nil, err
	}
	args = append(args, arg)

	// Parse additional function arguments if there is a comma.
	for {
		// If there's not a comma, stop parsing arguments.
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != comma {
			p.unscan()
			break
		}

		// Parse an expression argument.
		arg, err := p.ParseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}

	// There should be a right parentheses at the end.
	if tok, pos, lit := p.scan(); tok != rparen {
		return nil, newParseError(tokstr(tok, lit), []string{")"}, pos, p.expr)
	}

	fn := &Function{Name: name, Args: args}

	if err := fn.validate(); err != nil {
		return nil, err
	}

	return fn, nil
}

// scan returns the next token from the underlying scanner.
func (p *Parser) scan() (tok token, pos int, lit string) { return p.s.scan() }

// scanIgnoreWhitespace scans the next non-whitespace.
func (p *Parser) scanIgnoreWhitespace() (tok token, pos int, lit string) {
	for {
		tok, pos, lit = p.scan()
		if tok == ws {
			continue
		}
		return
	}
}

// unscan pushes the previously read token back onto the buffer.
func (p *Parser) unscan() { p.s.unscan() }
