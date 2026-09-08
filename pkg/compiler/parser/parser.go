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

package parser

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
)

// Parser builds AST expressions from the condition string.
type Parser struct {
	s    *lexer.Scanner
	c    *config.Filters
	expr string
}

func Parse(expr string) (ast.Expr, error) {
	return NewParser(expr).ParseExpr()
}

// NewParser builds a new parser instance from the expression string.
func NewParser(expr string) *Parser {
	return &Parser{s: lexer.NewScanner(strings.NewReader(expr)), expr: expr}
}

// NewParserWithConfig builds a new parser instance with filters config.
func NewParserWithConfig(expr string, config *config.Filters) *Parser {
	return &Parser{s: lexer.NewScanner(strings.NewReader(expr)), expr: expr, c: config}
}

func (p *Parser) ParseExpr() (ast.Expr, error) {
	tok, _, _ := p.scanIgnoreWhitespace()
	switch tok {
	case lexer.Seq:
		return p.parseSequenceExpr()
	default:
		p.unscan()
		return p.parseBinaryExpr()
	}
}

// parseSequenceExpr parses the collection of sequence steps with possible join
// statements and time frame constraints. This method assumes the SEQUENCE token
// has already been consumed.
func (p *Parser) parseSequenceExpr() (ast.Expr, error) {
	var steps []ast.SequenceStep

	seq := &ast.SequenceExpr{}

	// parse optional max span
	tok, _, _ := p.scanIgnoreWhitespace()
	if tok == lexer.MaxSpan {
		var err error
		seq.MaxSpan, err = p.parseDuration()
		if err != nil {
			return nil, err
		}
		if seq.MaxSpan > time.Hour*4 {
			return nil, fmt.Errorf("maximum span %v cannot be greater than 4h", seq.MaxSpan)
		}
	} else {
		p.unscan()
	}

	// parse optional global link
	tok, _, _ = p.scanIgnoreWhitespace()
	if tok == lexer.By {
		tok, pos, lit := p.scanIgnoreWhitespace()
		if !fields.IsField(lit) {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field"}, pos, p.expr)
		}
		var err error
		field, err := p.parseField(lit)
		if err != nil {
			return nil, err
		}

		seqLink := &ast.SequenceLink{Fields: []*ast.FieldLiteral{field}}

		// handle multiple join fields separated by comma
		for {
			if tok, _, _ := p.scanIgnoreWhitespace(); tok != lexer.Comma {
				p.unscan()
				break
			}

			tok, pos, lit := p.scanIgnoreWhitespace()
			if !fields.IsField(lit) {
				return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field"}, pos, p.expr)
			}
			field, err := p.parseField(lit)
			if err != nil {
				return nil, err
			}

			seqLink.Fields = append(seqLink.Fields, field)
		}

		seq.By = seqLink
	} else {
		p.unscan()
	}

	// parse sequence steps
	for {
		if tok, _, _ := p.scanIgnoreWhitespace(); tok == lexer.EOF {
			if len(steps) < 1 {
				return nil, fmt.Errorf("%s: sequences require at least two steps", p.expr)
			}

			const maxSteps = 5
			if len(steps) > maxSteps {
				return nil, fmt.Errorf("%s: maximum number of steps reached", p.expr)
			}
			seq.Steps = steps

			if seq.HasImpairBy() {
				return nil, fmt.Errorf("%s: all steps require the 'by' statement", p.expr)
			}
			if seq.HasIncompatibleConstraints() {
				return nil, fmt.Errorf("%s: sequence mixes global and per-expression 'by' statements", p.expr)
			}

			return seq, nil
		}
		p.unscan()

		tok, posStart, lit := p.scanIgnoreWhitespace()
		if tok != lexer.Pipe {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"|"}, posStart, p.expr)
		}
		expr, err := p.parseBinaryExpr()
		if err != nil {
			return nil, err
		}
		tok, posEnd, lit := p.scanIgnoreWhitespace()
		if tok != lexer.Pipe {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"|"}, posEnd, p.expr)
		}

		var step ast.SequenceStep

		// parse sequence BY or AS constraints (links)
		tok, _, _ = p.scanIgnoreWhitespace()
		switch tok {
		case lexer.By:
			tok, pos, lit := p.scanIgnoreWhitespace()
			if !fields.IsField(lit) {
				return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field"}, pos, p.expr)
			}
			field, err := p.parseField(lit)
			if err != nil {
				return nil, err
			}

			seqLink := &ast.SequenceLink{Fields: []*ast.FieldLiteral{field}}

			// handle multiple join fields separated by comma
			for {
				if tok, _, _ := p.scanIgnoreWhitespace(); tok != lexer.Comma {
					p.unscan()
					break
				}

				tok, pos, lit := p.scanIgnoreWhitespace()
				if !fields.IsField(lit) {
					return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field"}, pos, p.expr)
				}
				field, err := p.parseField(lit)
				if err != nil {
					return nil, err
				}

				seqLink.Fields = append(seqLink.Fields, field)
			}
			step = ast.SequenceStep{Expr: expr, By: seqLink}
		case lexer.As:
			tok, pos, lit := p.scanIgnoreWhitespace()
			if tok != lexer.BoundVar {
				return nil, newParseError(lexer.Tokstr(tok, lit), []string{"bound var"}, pos, p.expr)
			}
			step = ast.SequenceStep{Expr: expr, BoundVar: lit}
		default:
			step = ast.SequenceStep{Expr: expr}
			p.unscan()
		}

		steps = append(steps, step)
	}
}

// parseBinaryExpr parses the binary expression by building the expression tree.
func (p *Parser) parseBinaryExpr() (ast.Expr, error) {
	var err error
	root := &ast.BinaryExpr{}
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
		if !op.IsOperator() {
			p.unscan()
			if op != lexer.EOF && op != lexer.Rparen && op != lexer.Comma && op != lexer.Pipe {
				return nil, newParseError(lexer.Tokstr(op, lit), []string{"operator", "')'", "','", "'|'"}, pos, p.expr)
			}
			return root.RHS, nil
		}

		if op == lexer.In || op == lexer.IIn {
			// expect LPAREN after in
			tok, pos, lit := p.scanIgnoreWhitespace()
			p.unscan()
			if tok != lexer.Lparen && (p.c != nil && !p.c.IsMacroList(lit)) {
				return nil, newParseError(lexer.Tokstr(op, lit), []string{"'('"}, pos, p.expr)
			}
		}

		if op == lexer.Not {
			// handle infix negation
			op1, pos, lit := p.scanIgnoreWhitespace()
			if !op1.IsOperator() {
				return nil, newParseError(lexer.Tokstr(op1, lit), []string{"operator"}, pos, p.expr)
			}
			rhs, err := p.parseUnaryExpr()
			if err != nil {
				return nil, err
			}

			for node := root; ; {
				r, ok := node.RHS.(*ast.BinaryExpr)
				if !ok || r.Op.Precedence() >= op1.Precedence() {
					node.RHS = &ast.NotExpr{Expr: &ast.BinaryExpr{LHS: node.RHS, RHS: rhs, Op: op1}}
					break
				}
				node = r
			}
			continue
		}

		rhs, err := p.parseUnaryExpr()
		if err != nil {
			return nil, err
		}

		// find the right spot in the tree to add the new expression by
		// descending the RHS of the expression tree until we reach the last
		// BinaryExpr or a BinaryExpr whose RHS has an operator with
		// precedence >= the operator being added.
		for node := root; ; {
			r, ok := node.RHS.(*ast.BinaryExpr)
			if !ok || r.Op.Precedence() >= op.Precedence() {
				// add the new expression here and break
				node.RHS = &ast.BinaryExpr{LHS: node.RHS, RHS: rhs, Op: op}
				break
			}
			node = r
		}
	}
}

// parseUnaryExpr parses an non-binary expression.
func (p *Parser) parseUnaryExpr() (ast.Expr, error) {
	// If the first token is a LPAREN then parse it as its own grouped expression.
	if tok, _, _ := p.scanIgnoreWhitespace(); tok == lexer.Lparen {
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
			if tok, pos, lit := p.scanIgnoreWhitespace(); tok != lexer.Rparen {
				return nil, newParseError(lexer.Tokstr(tok, lit), []string{"')'"}, pos, p.expr)
			}
			return &ast.ParenExpr{Expr: expr}, nil
		}

		// Expect an RPAREN at the end of list
		if tok, pos, lit := p.scanIgnoreWhitespace(); tok != lexer.Rparen {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"')'"}, pos, p.expr)
		}

		return &ast.ListLiteral{Values: tagKeys}, nil
	}

	// handle unary negation
	p.unscan()
	if tok, pos, lit := p.scanIgnoreWhitespace(); tok == lexer.Not {
		expr, err := p.parseUnaryExpr()
		if err != nil {
			return nil, err
		}

		if f, ok := expr.(*ast.FieldLiteral); ok && !fields.IsBoolean(f.Field) {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"boolean field", "("}, pos, p.expr)
		}

		return &ast.NotExpr{Expr: expr}, nil
	}

	p.unscan()

	tok, pos, lit := p.scanIgnoreWhitespace()
	switch tok {
	case lexer.Ident:
		if fields.IsField(lit) {
			return p.parseField(lit)
		}

		if tok0, _, _ := p.scan(); tok0 == lexer.Lparen {
			return p.parseFunction(lit)
		}
		// unscan lparen token
		p.unscan()

		// expand macros
		if p.c != nil {
			macro := p.c.GetMacro(lit)
			if macro != nil {
				if macro.Expr != "" {
					p := NewParserWithConfig(macro.Expr, p.c)
					expr, err := p.ParseExpr()
					if err != nil {
						return nil, multierror.WrapWithSeparator("\n", fmt.Errorf("syntax error in %q macro", lit), err)
					}
					return expr, nil
				}
				return &ast.ListLiteral{Values: macro.List}, nil
			}
			// unscan ident
			p.unscan()
		}
	case lexer.IP:
		return &ast.IPLiteral{Value: net.ParseIP(lit)}, nil
	case lexer.Str:
		return &ast.StringLiteral{Value: lit}, nil
	case lexer.BoundVar:
		n := strings.Index(lit, ".")
		if n == -1 {
			return &ast.BareBoundVariableLiteral{Value: lit}, nil
		}

		// for recognized segment return bound segment literal
		s := lit[n+1:]
		if fields.IsSegment(s) {
			return &ast.BoundSegmentLiteral{Value: lit, BoundVar: ast.BareBoundVariableLiteral{Value: lit[1:n]}, Segment: fields.Segment(s)}, nil
		}

		// parse field literal for recognized field
		if fields.IsField(s) {
			field, err := p.parseField(s)
			if err != nil {
				return nil, err
			}
			return &ast.BoundFieldLiteral{Value: lit, BoundVar: ast.BareBoundVariableLiteral{Value: lit[1:n]}, Field: field}, nil
		}

		return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field/segment after bound ref"}, pos+n, p.expr)
	case lexer.True, lexer.False:
		return &ast.BoolLiteral{Value: tok == lexer.True}, nil
	case lexer.Integer:
		v, err := strconv.ParseInt(lit, 10, 64)
		if err != nil {
			// The literal may be too large to fit into an int64. If it is, use an unsigned integer.
			// The check for negative numbers is handled somewhere else so this should always be a positive number.
			if v, err := strconv.ParseUint(lit, 10, 64); err == nil {
				return &ast.UnsignedLiteral{Value: v}, nil
			}
			return nil, &ParseError{Message: "unable to parse integer", Pos: pos}
		}
		return &ast.IntegerLiteral{Value: v}, nil
	case lexer.Decimal:
		v, err := strconv.ParseFloat(lit, 64)
		if err != nil {
			return nil, &ParseError{Message: "unable to parse decimal", Pos: pos}
		}
		return &ast.DecimalLiteral{Value: v}, nil
	}

	expectations := []string{"field", "bound field", "string", "number", "bool", "ip", "function"}
	if tok == lexer.BadIP {
		expectations = []string{"a valid IP address"}
	}
	if tok == lexer.Badesc || tok == lexer.Badstr {
		expectations = []string{"a valid string but bad string or escape found"}
	}

	return nil, newParseError(lexer.Tokstr(tok, lit), expectations, pos, p.expr)
}

// parseField parses the field and its argument. This method
// assumes the field name has been consumed.
func (p *Parser) parseField(name string) (*ast.FieldLiteral, error) {
	argument := fields.ArgumentOf(name)

	// parse field argument
	tok, pos, lit := p.scan()
	if tok == lexer.LBracket {
		arg, pos, lit := p.scan()
		if arg != lexer.Ident && arg != lexer.Integer {
			return nil, newParseError(lexer.Tokstr(arg, lit), []string{"ident", "integer"}, pos, p.expr)
		}

		// field argument given, but the field doesn't require one
		if argument == nil {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field without argument"}, pos, p.expr)
		}

		// validate argument
		if argument != nil && !argument.Validate(lit) {
			exp := fmt.Sprintf("a valid field argument matching the pattern %s", argument.Pattern)
			return nil, newParseError(lexer.Tokstr(arg, lit), []string{exp}, pos, p.expr)
		}

		if tok, pos, lit := p.scan(); tok != lexer.RBracket {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"]"}, pos, p.expr)
		}

		return &ast.FieldLiteral{Value: name, Field: fields.Field(name), Arg: lit}, nil
	} else {
		// unscan lbracket
		p.unscan()
		// field argument not given, but it is required
		if argument != nil && !argument.Optional {
			return nil, newParseError(lexer.Tokstr(tok, lit), []string{"field argument"}, pos, p.expr)
		}

		return &ast.FieldLiteral{Value: name, Field: fields.Field(name)}, nil
	}
}

// parseList parses the list of strings. This method assumes the
// LPAREN token has been consumed.
func (p *Parser) parseList() ([]string, error) {
	tok, pos, lit := p.scanIgnoreWhitespace()
	if tok != lexer.Str && tok != lexer.IP && tok != lexer.Integer {
		return []string{}, newParseError(lexer.Tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
	}
	idents := []string{lit}

	// parse remaining identifiers
	for {
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != lexer.Comma {
			p.unscan()
			return idents, nil
		}

		tok, pos, lit := p.scanIgnoreWhitespace()
		if tok != lexer.Str && tok != lexer.IP && tok != lexer.Integer {
			return []string{}, newParseError(lexer.Tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
		}

		idents = append(idents, lit)
	}
}

// parseFunction parses a function call. This method assumes
// the function name and LPAREN have been consumed.
func (p *Parser) parseFunction(name string) (*ast.Function, error) {
	name = strings.ToLower(name)
	args := make([]ast.Expr, 0)

	// If there's a right paren then just return immediately.
	// This is the case for functions without arguments
	if tok, _, _ := p.scan(); tok == lexer.Rparen {
		fn := &ast.Function{Name: name}
		if err := fn.Validate(); err != nil {
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
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != lexer.Comma {
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
	if tok, pos, lit := p.scan(); tok != lexer.Rparen {
		return nil, newParseError(lexer.Tokstr(tok, lit), []string{")"}, pos, p.expr)
	}

	fn := &ast.Function{Name: name, Args: args}

	if err := fn.Validate(); err != nil {
		return nil, err
	}

	return fn, nil
}

// parseDuration parses a string and returns a duration literal.
func (p *Parser) parseDuration() (time.Duration, error) {
	tok, pos, lit := p.scanIgnoreWhitespace()
	if tok != lexer.Duration {
		return 0, newParseError(lexer.Tokstr(tok, lit), []string{"duration"}, pos, p.expr)
	}

	d, err := parseDuration(lit)
	if err != nil {
		return 0, &ParseError{Message: err.Error(), Pos: pos}
	}

	return d, nil
}

// ErrInvalidDuration is returned when parsing a malformed duration.
var ErrInvalidDuration = errors.New("invalid duration")

// parseDuration parses a time duration from a string.
func parseDuration(s string) (time.Duration, error) {
	// Return an error if the string is blank or one character
	if len(s) < 2 {
		return 0, ErrInvalidDuration
	}

	// Split string into individual runes.
	a := []rune(s)

	// Start with a zero duration.
	var d time.Duration
	i := 0

	// Check for a negative.
	isNegative := false
	if a[i] == '-' {
		isNegative = true
		i++
	}

	var measure int64
	var unit string

	// Parsing loop.
	for i < len(a) {
		// Find the number portion.
		start := i
		for ; i < len(a) && lexer.IsDigit(a[i]); i++ {
			// Scan for the digits.
		}

		// Check if we reached the end of the string prematurely.
		if i >= len(a) || i == start {
			return 0, ErrInvalidDuration
		}

		// Parse the numeric part.
		n, err := strconv.ParseInt(string(a[start:i]), 10, 64)
		if err != nil {
			return 0, ErrInvalidDuration
		}
		measure = n

		// Extract the unit of measure.
		// If the last two characters are "ms" then parse as milliseconds.
		// Otherwise, just use the last character as the unit of measure.
		unit = string(a[i])
		switch a[i] {
		case 'n':
			if i+1 < len(a) && a[i+1] == 's' {
				unit = string(a[i : i+2])
				d += time.Duration(n)
				i += 2
				continue
			}
			return 0, ErrInvalidDuration
		case 'u', 'µ':
			d += time.Duration(n) * time.Microsecond
		case 'm':
			if i+1 < len(a) && a[i+1] == 's' {
				unit = string(a[i : i+2])
				d += time.Duration(n) * time.Millisecond
				i += 2
				continue
			}
			d += time.Duration(n) * time.Minute
		case 's':
			d += time.Duration(n) * time.Second
		case 'h':
			d += time.Duration(n) * time.Hour
		case 'd':
			d += time.Duration(n) * 24 * time.Hour
		case 'w':
			d += time.Duration(n) * 7 * 24 * time.Hour
		default:
			return 0, ErrInvalidDuration
		}
		i++
	}

	// Check to see if we overflowed a duration
	if d < 0 && !isNegative {
		return 0, fmt.Errorf("overflowed duration %d%s: choose a smaller duration or INF", measure, unit)
	}

	if isNegative {
		d = -d
	}
	return d, nil
}

// scan returns the next token from the underlying scanner.
func (p *Parser) scan() (tok lexer.Token, pos int, lit string) { return p.s.Scan() }

// scanIgnoreWhitespace scans the next non-whitespace.
func (p *Parser) scanIgnoreWhitespace() (tok lexer.Token, pos int, lit string) {
	for {
		tok, pos, lit = p.scan()
		if tok == lexer.WS {
			continue
		}
		return
	}
}

// unscan pushes the previously read token back onto the buffer.
func (p *Parser) unscan() { p.s.Unscan() }
