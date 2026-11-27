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
	"net"
	"strconv"
	"strings"

	fuzzysearch "github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/util/sets"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
)

// compare applies the comparison operator to the operands that were already
// evaluated. The result is a bool, or nil if the expression is undefined, e.g.
// the operator doesn't apply to the type of the left operand. An operand pair
// the operator can't compare yields false for the equality and the relational
// operators, and the undefined value for every other one.
//
// The operands are dispatched by the type of the left operand, and the
// operator is decided within the family of the type, so there is no matrix of
// the types and the operators.
func compare(op lexer.Token, lhs, rhs any) any {
	var (
		res any
		ok  bool
	)
	switch l := lhs.(type) {
	case bool:
		res, ok = compareBool(op, l, rhs)
	case string:
		res, ok = compareString(op, l, rhs)
	case net.IP:
		res, ok = compareIP(op, l, rhs)
	case []string:
		res, ok = compareStrings(op, l, rhs)
	case []uint64:
		res, ok = compareUints(op, l, rhs)
	default:
		res, ok = compareNumber(op, lhs, rhs)
	}
	if ok {
		return res
	}
	return incomparable(op)
}

// incomparable is the result of the comparison the operator can't perform.
func incomparable(op lexer.Token) any {
	switch op {
	case lexer.Eq, lexer.IEq, lexer.Neq, lexer.Lt, lexer.Lte, lexer.Gt, lexer.Gte:
		return false
	}
	return nil
}

func compareBool(op lexer.Token, l bool, rhs any) (any, bool) {
	r, isBool := rhs.(bool)
	switch op {
	case lexer.Eq:
		return isBool && l == r, true
	case lexer.Neq:
		return isBool && l != r, true
	}
	return nil, false
}

// number is the numeric operand. A value is either signed, unsigned or
// floating point, which is all the comparison has to know about it.
type number struct {
	kind numKind
	i    int64
	u    uint64
	f    float64
}

type numKind uint8

const (
	kindSigned numKind = iota + 1
	kindUnsigned
	kindFloat
)

// width is the Go type of the numeric operand. It decides which operand
// pairs are comparable, since the expressions never compared every pair.
type width uint8

const (
	wInt width = iota + 1
	wInt32
	wInt64
	wUint8
	wUint16
	wUint32
	wUint64
	wFloat64
)

func toNumber(v any) (number, width, bool) {
	switch v := v.(type) {
	case int:
		return number{kind: kindSigned, i: int64(v)}, wInt, true
	case int32:
		return number{kind: kindSigned, i: int64(v)}, wInt32, true
	case int64:
		return number{kind: kindSigned, i: v}, wInt64, true
	case uint8:
		return number{kind: kindUnsigned, u: uint64(v)}, wUint8, true
	case uint16:
		return number{kind: kindUnsigned, u: uint64(v)}, wUint16, true
	case uint32:
		return number{kind: kindUnsigned, u: uint64(v)}, wUint32, true
	case uint64:
		return number{kind: kindUnsigned, u: v}, wUint64, true
	case float64:
		return number{kind: kindFloat, f: v}, wFloat64, true
	}
	return number{}, 0, false
}

func (n number) float() float64 {
	switch n.kind {
	case kindSigned:
		return float64(n.i)
	case kindUnsigned:
		return float64(n.u)
	}
	return n.f
}

// comparableWidths reports whether the type of the left operand can be compared
// to the type of the right one. The scalar types are compared with the
// floating point and the 64-bit types, and the unsigned 32 and 16-bit ones
// with the smaller signed types too.
func comparableWidths(l, r width) bool {
	switch l {
	case wInt, wUint8, wInt64, wUint64, wFloat64:
		return r == wFloat64 || r == wInt64 || r == wUint64
	case wUint32:
		return r == wFloat64 || r == wInt32 || r == wInt64 || r == wUint32
	case wUint16:
		return r == wFloat64 || r == wInt32 || r == wInt64 || r == wUint16
	}
	return false
}

func compareNumber(op lexer.Token, lhs, rhs any) (any, bool) {
	l, lw, ok := toNumber(lhs)
	if !ok {
		return nil, false
	}
	if op == lexer.In {
		return numberIn(l, lw, rhs)
	}
	r, rw, ok := toNumber(rhs)
	if !ok {
		// the left operand is numeric, so the operators below are defined, and
		// the right operand of another type just doesn't match
		return false, isOrdering(op)
	}
	if !isOrdering(op) {
		return nil, false
	}
	if !comparableWidths(lw, rw) {
		return false, true
	}
	return order(op, l, r), true
}

func isOrdering(op lexer.Token) bool {
	switch op {
	case lexer.Eq, lexer.Neq, lexer.Lt, lexer.Lte, lexer.Gt, lexer.Gte:
		return true
	}
	return false
}

// order compares the numbers by value, regardless of their signedness. A
// negative number is less than any unsigned one.
func order(op lexer.Token, l, r number) bool {
	if l.kind == kindFloat || r.kind == kindFloat {
		lf, rf := l.float(), r.float()
		switch op {
		case lexer.Eq:
			return lf == rf
		case lexer.Neq:
			return lf != rf
		case lexer.Lt:
			return lf < rf
		case lexer.Lte:
			return lf <= rf
		case lexer.Gt:
			return lf > rf
		default:
			return lf >= rf
		}
	}

	var c int
	switch {
	case l.kind == kindSigned && r.kind == kindSigned:
		c = cmp3(l.i < r.i, l.i > r.i)
	case l.kind == kindUnsigned && r.kind == kindUnsigned:
		c = cmp3(l.u < r.u, l.u > r.u)
	case l.kind == kindSigned:
		if l.i < 0 {
			c = -1
		} else {
			c = cmp3(uint64(l.i) < r.u, uint64(l.i) > r.u)
		}
	default:
		if r.i < 0 {
			c = 1
		} else {
			c = cmp3(l.u < uint64(r.i), l.u > uint64(r.i))
		}
	}

	switch op {
	case lexer.Eq:
		return c == 0
	case lexer.Neq:
		return c != 0
	case lexer.Lt:
		return c < 0
	case lexer.Lte:
		return c <= 0
	case lexer.Gt:
		return c > 0
	default:
		return c >= 0
	}
}

func cmp3(less, greater bool) int {
	switch {
	case less:
		return -1
	case greater:
		return 1
	}
	return 0
}

// numberIn handles the IN operator, which the numbers support against the
// lists the field types are matched with: the ports against a list of
// numbers, and the unsigned integers against a list of numeric strings.
func numberIn(l number, lw width, rhs any) (any, bool) {
	switch lw {
	case wInt:
		ports, ok := rhs.([]uint16)
		if !ok {
			return nil, false
		}
		for _, p := range ports {
			if int64(p) == l.i {
				return true, true
			}
		}
		return false, true
	case wUint32, wUint16:
		strs, ok := rhs.([]string)
		if !ok {
			return nil, false
		}
		bits := 32
		if lw == wUint16 {
			bits = 16
		}
		for _, s := range strs {
			n, err := strconv.ParseUint(s, 10, bits)
			if err != nil {
				continue
			}
			if n == l.u {
				return true, true
			}
		}
		return false, true
	}
	return nil, false
}

// compareUints compares the slice of the unsigned numbers, e.g. the callstack
// addresses, with a number. The comparison holds if any of the elements holds.
func compareUints(op lexer.Token, l []uint64, rhs any) (any, bool) {
	if op != lexer.Gt && op != lexer.Gte {
		return nil, false
	}
	var r uint64
	switch rhs := rhs.(type) {
	case uint64:
		r = rhs
	case int64:
		r = uint64(rhs)
	default:
		return nil, false
	}
	for _, i := range l {
		if (op == lexer.Gt && i > r) || (op == lexer.Gte && i >= r) {
			return true, true
		}
	}
	return false, true
}

// matcher is the string predicate behind the operator. The case-insensitive
// operators fold both operands to lower case, and the fuzzy ones fold on their own.
type matcher struct {
	match func(s, pattern string) bool
	fold  bool
}

func stringMatcher(op lexer.Token) (matcher, bool) {
	switch op {
	case lexer.Contains:
		return matcher{match: strings.Contains}, true
	case lexer.IContains:
		return matcher{match: strings.Contains, fold: true}, true
	case lexer.Startswith:
		return matcher{match: strings.HasPrefix}, true
	case lexer.IStartswith:
		return matcher{match: strings.HasPrefix, fold: true}, true
	case lexer.Endswith:
		return matcher{match: strings.HasSuffix}, true
	case lexer.IEndswith:
		return matcher{match: strings.HasSuffix, fold: true}, true
	case lexer.Matches:
		return matcher{match: func(s, p string) bool { return wildcard.Match(p, s, true) }}, true
	case lexer.IMatches:
		return matcher{match: func(s, p string) bool { return wildcard.Match(p, s, false) }}, true
	case lexer.Fuzzy:
		return matcher{match: func(s, p string) bool { return fuzzysearch.Match(p, s) }}, true
	case lexer.IFuzzy:
		return matcher{match: func(s, p string) bool { return fuzzysearch.MatchFold(p, s) }}, true
	case lexer.Fuzzynorm:
		return matcher{match: func(s, p string) bool { return fuzzysearch.MatchNormalized(p, s) }}, true
	case lexer.IFuzzynorm:
		return matcher{match: func(s, p string) bool { return fuzzysearch.MatchNormalizedFold(p, s) }}, true
	}
	return matcher{}, false
}

// matchAny reports whether the string matches the pattern, or any of the
// patterns if the right operand is a list. Another operand type never matches.
func (m matcher) matchAny(s string, rhs any) bool {
	if m.fold {
		s = strings.ToLower(s)
	}
	switch p := rhs.(type) {
	case string:
		return m.matchOne(s, p)
	case []string:
		for _, pat := range p {
			if m.matchOne(s, pat) {
				return true
			}
		}
	}
	return false
}

func (m matcher) matchOne(s, pattern string) bool {
	if m.fold {
		pattern = strings.ToLower(pattern)
	}
	return m.match(s, pattern)
}

func compareString(op lexer.Token, l string, rhs any) (any, bool) {
	switch op {
	case lexer.Eq, lexer.IEq, lexer.Neq:
		r, ok := rhs.(string)
		if !ok {
			return false, true
		}
		switch op {
		case lexer.Eq:
			return l == r, true
		case lexer.IEq:
			return strings.EqualFold(l, r), true
		}
		return l != r, true
	case lexer.In, lexer.IIn:
		list, ok := rhs.([]string)
		if !ok {
			return false, true
		}
		for _, s := range list {
			if s == l || (op == lexer.IIn && strings.EqualFold(s, l)) {
				return true, true
			}
		}
		return false, true
	}
	m, ok := stringMatcher(op)
	if !ok {
		return nil, false
	}
	return m.matchAny(l, rhs), true
}

func compareIP(op lexer.Token, l net.IP, rhs any) (any, bool) {
	switch op {
	case lexer.Eq, lexer.Neq:
		r, ok := rhs.(net.IP)
		if !ok {
			return false, true
		}
		return l.Equal(r) == (op == lexer.Eq), true
	case lexer.In:
		switch list := rhs.(type) {
		case []net.IP:
			for _, ip := range list {
				if ip.Equal(l) {
					return true, true
				}
			}
		case []string:
			// string lists are accepted for backward compatibility
			for _, s := range list {
				if net.ParseIP(s).Equal(l) {
					return true, true
				}
			}
		}
		return false, true
	case lexer.Startswith, lexer.Endswith:
		r, ok := rhs.(string)
		if !ok {
			return false, true
		}
		if op == lexer.Startswith {
			return strings.HasPrefix(l.String(), r), true
		}
		return strings.HasSuffix(l.String(), r), true
	}
	return nil, false
}

// compareStrings compares the slice of strings. Whether the slice satisfies
// the operator depends on any of its elements matching, or on the set
// relation, for the intersection operators.
func compareStrings(op lexer.Token, l []string, rhs any) (any, bool) {
	switch op {
	case lexer.Intersects, lexer.IIntersects:
		r, ok := rhs.([]string)
		if !ok {
			return false, true
		}
		return len(sets.IntersectionStrings(l, r, op == lexer.IIntersects)) == len(r), true
	case lexer.In, lexer.IIn:
		eq := func(a, b string) bool { return a == b }
		if op == lexer.IIn {
			eq = strings.EqualFold
		}
		return anyPair(l, rhs, eq, true), true
	case lexer.Contains:
		return anyPair(l, rhs, strings.Contains, true), true
	case lexer.IContains, lexer.Startswith, lexer.IStartswith, lexer.Endswith,
		lexer.IEndswith, lexer.Matches, lexer.IMatches:
		m, _ := stringMatcher(op)
		return anyPair(l, rhs, func(s, p string) bool {
			if m.fold {
				return m.match(strings.ToLower(s), strings.ToLower(p))
			}
			return m.match(s, p)
		}, !isListOnly(op)), true
	}
	return nil, false
}

// isListOnly tells whether the operator against the slice of strings accepts
// only the list on the right side. The operators that accept a lone string
// are IN, IIN and CONTAINS.
func isListOnly(op lexer.Token) bool {
	switch op {
	case lexer.IContains, lexer.Startswith, lexer.IStartswith, lexer.Endswith,
		lexer.IEndswith, lexer.Matches, lexer.IMatches:
		return true
	}
	return false
}

// anyPair reports whether any of the strings matches the string, or any of the
// strings of the list, on the right side.
func anyPair(l []string, rhs any, match func(s, p string) bool, allowString bool) bool {
	switch r := rhs.(type) {
	case string:
		if !allowString {
			return false
		}
		for _, s := range l {
			if match(s, r) {
				return true
			}
		}
	case []string:
		for _, p := range r {
			for _, s := range l {
				if match(s, p) {
					return true
				}
			}
		}
	}
	return false
}
