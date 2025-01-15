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
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"net"
	"strconv"
	"strings"
	"time"
)

// Parser builds the binary expression tree from the filter string.
type Parser struct {
	s    *bufScanner
	c    *config.Filters
	expr string
}

// NewParser builds a new parser instance from the expression string.
func NewParser(expr string) *Parser {
	return &Parser{s: newBufScanner(strings.NewReader(expr)), expr: expr}
}

// NewParserWithConfig builds a new parser instance with filters config.
func NewParserWithConfig(expr string, config *config.Filters) *Parser {
	return &Parser{s: newBufScanner(strings.NewReader(expr)), expr: expr, c: config}
}

// ParseSequence parses the collection of binary expressions with possible join
// statements and time frame constraints. This method assumes the SEQUENCE token
// has already been consumed.
func (p *Parser) ParseSequence() (*Sequence, error) {
	seq := &Sequence{}
	var exprs []SequenceExpr

	// parse optional max span
	tok, _, _ := p.scanIgnoreWhitespace()
	if tok == MaxSpan {
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

	// parse optional global join
	tok, _, _ = p.scanIgnoreWhitespace()
	if tok == By {
		tok, pos, lit := p.scanIgnoreWhitespace()
		if tok != Field {
			return nil, newParseError(tokstr(tok, lit), []string{"field"}, pos, p.expr)
		}
		seq.By = fields.Field(lit)
	} else {
		p.unscan()
	}

	// parse sequence expressions
	for {
		if tok, _, _ := p.scanIgnoreWhitespace(); tok == EOF {
			if len(exprs) < 1 {
				return nil, fmt.Errorf("%s: sequences require at least two expressions", p.expr)
			}
			const maxExpressions = 5
			if len(exprs) > maxExpressions {
				return nil, fmt.Errorf("%s: maximum number of expressions reached", p.expr)
			}
			seq.Expressions = exprs
			if seq.impairBy() {
				return nil, fmt.Errorf("%s: all expressions require the 'by' statement", p.expr)
			}
			if seq.incompatibleConstraints() {
				return nil, fmt.Errorf("%s: sequence mixes global and per-expression 'by' statements", p.expr)
			}
			seq.init()
			return seq, nil
		}
		p.unscan()

		tok, posStart, lit := p.scanIgnoreWhitespace()
		if tok != Pipe {
			return nil, newParseError(tokstr(tok, lit), []string{"|"}, posStart, p.expr)
		}
		expr, err := p.ParseExpr()
		if err != nil {
			return nil, err
		}
		tok, posEnd, lit := p.scanIgnoreWhitespace()
		if tok != Pipe {
			return nil, newParseError(tokstr(tok, lit), []string{"|"}, posEnd, p.expr)
		}

		var seqexpr SequenceExpr
		tok, _, _ = p.scanIgnoreWhitespace()
		switch tok {
		case By:
			tok, pos, lit := p.scanIgnoreWhitespace()
			if tok != Field {
				return nil, newParseError(tokstr(tok, lit), []string{"field"}, pos, p.expr)
			}
			seqexpr = SequenceExpr{Expr: expr, By: fields.Field(lit)}
		case As:
			tok, pos, lit := p.scanIgnoreWhitespace()
			if tok != Ident {
				return nil, newParseError(tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
			}
			seqexpr = SequenceExpr{Expr: expr, Alias: lit}
		default:
			seqexpr = SequenceExpr{Expr: expr}
			p.unscan()
		}
		seqexpr.init()
		seqexpr.walk()
		exprs = append(exprs, seqexpr)
	}
}

// IsSequence checks whether the expression given to the parser is a sequence.
func (p *Parser) IsSequence() bool {
	tok, _, _ := p.scanIgnoreWhitespace()
	if tok == Seq {
		return true
	}
	p.unscan()
	return false
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
			if op != EOF && op != Rparen && op != Comma && op != Pipe {
				return nil, newParseError(tokstr(op, lit), []string{"operator", "')'", "','", "'|'"}, pos, p.expr)
			}
			return root.RHS, nil
		}

		if op == In || op == IIn {
			// expect LPAREN after in
			tok, pos, lit := p.scanIgnoreWhitespace()
			p.unscan()
			if tok != Lparen && (p.c != nil && !p.c.IsMacroList(lit)) {
				return nil, newParseError(tokstr(op, lit), []string{"'('"}, pos, p.expr)
			}
		}

		var rhs Expr
		switch op {
		case Not:
			// the first variant of the negation operator.
			// The operator that is negated appears immediately
			// after the `not` operator, e.g. ps.name not in ('cmd.exe')
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
		default:
			op1, _, _ := p.scanIgnoreWhitespace()
			// if the negation appears after the operator
			// try to parse an entire binary expr and wrap
			// it inside the `not` expression. This is the
			// second variant of the negating expressions, e.g.
			// ps.name = 'cmd.exe' and not (ps.name in ('powershell.exe'))
			if op1 == Not {
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
				if op == Not {
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
	if tok, _, _ := p.scanIgnoreWhitespace(); tok == Lparen {
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
			if tok, pos, lit := p.scanIgnoreWhitespace(); tok != Rparen {
				return nil, newParseError(tokstr(tok, lit), []string{"')'"}, pos, p.expr)
			}
			return &ParenExpr{Expr: expr}, nil
		}

		// Expect an RPAREN at the end of list
		if tok, pos, lit := p.scanIgnoreWhitespace(); tok != Rparen {
			return nil, newParseError(tokstr(tok, lit), []string{"')'"}, pos, p.expr)
		}

		return &ListLiteral{Values: tagKeys}, nil
	}

	p.unscan()

	tok, pos, lit := p.scanIgnoreWhitespace()
	switch tok {
	case Ident:
		if tok0, _, _ := p.scan(); tok0 == Lparen {
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
				return &ListLiteral{Values: macro.List}, nil
			}
			// unscan ident
			p.unscan()
		}
	case IP:
		return &IPLiteral{Value: net.ParseIP(lit)}, nil
	case Str:
		return &StringLiteral{Value: lit}, nil
	case Field:
		return &FieldLiteral{Value: lit}, nil
	case BoundField:
		n := strings.Index(lit, ".")
		if n > 0 && fields.Lookup(lit[n+1:]) == "" && !fields.IsSegment(lit[n+1:]) {
			return nil, newParseError(tokstr(tok, lit), []string{"field/segment after bound ref"}, pos+n, p.expr)
		}
		return &BoundFieldLiteral{Value: lit}, nil
	case True, False:
		return &BoolLiteral{Value: tok == True}, nil
	case Integer:
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
	case Decimal:
		v, err := strconv.ParseFloat(lit, 64)
		if err != nil {
			return nil, &ParseError{Message: "unable to parse decimal", Pos: pos}
		}
		return &DecimalLiteral{Value: v}, nil
	}

	expectations := []string{"field", "bound field", "string", "number", "bool", "ip", "function"}
	if tok == BadIP {
		expectations = []string{"a valid IP address"}
	}
	if tok == Badesc || tok == Badstr {
		expectations = []string{"a valid string but bad string or escape found"}
	}

	return nil, newParseError(tokstr(tok, lit), expectations, pos, p.expr)
}

func (p *Parser) parseList() ([]string, error) {
	tok, pos, lit := p.scanIgnoreWhitespace()
	if tok != Str && tok != IP && tok != Integer {
		return []string{}, newParseError(tokstr(tok, lit), []string{"identifier"}, pos, p.expr)
	}
	idents := []string{lit}

	// parse remaining identifiers
	for {
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != Comma {
			p.unscan()
			return idents, nil
		}

		tok, pos, lit := p.scanIgnoreWhitespace()
		if tok != Str && tok != IP && tok != Integer {
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
	if tok, _, _ := p.scan(); tok == Rparen {
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
		if tok, _, _ := p.scanIgnoreWhitespace(); tok != Comma {
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
	if tok, pos, lit := p.scan(); tok != Rparen {
		return nil, newParseError(tokstr(tok, lit), []string{")"}, pos, p.expr)
	}

	fn := &Function{Name: name, Args: args}

	if err := fn.validate(); err != nil {
		return nil, err
	}

	return fn, nil
}

// parseDuration parses a string and returns a duration literal.
func (p *Parser) parseDuration() (time.Duration, error) {
	tok, pos, lit := p.scanIgnoreWhitespace()
	if tok != Duration {
		return 0, newParseError(tokstr(tok, lit), []string{"duration"}, pos, p.expr)
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
		for ; i < len(a) && isDigit(a[i]); i++ {
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
func (p *Parser) scan() (tok token, pos int, lit string) { return p.s.scan() }

// scanIgnoreWhitespace scans the next non-whitespace.
func (p *Parser) scanIgnoreWhitespace() (tok token, pos int, lit string) {
	for {
		tok, pos, lit = p.scan()
		if tok == WS {
			continue
		}
		return
	}
}

// unscan pushes the previously read token back onto the buffer.
func (p *Parser) unscan() { p.s.unscan() }
