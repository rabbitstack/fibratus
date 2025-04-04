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
	fuzzysearch "github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/rabbitstack/fibratus/pkg/util/sets"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	"net"
	"strconv"
	"strings"
)

// Eval evaluates expr against a map that contains the field values.
func Eval(expr Expr, m map[string]interface{}, useFuncValuer bool) bool {
	var eval ValuerEval
	if useFuncValuer {
		eval = ValuerEval{Valuer: MultiValuer(MapValuer(m), FunctionValuer{m})}
	} else {
		eval = ValuerEval{Valuer: MapValuer(m)}
	}
	v, ok := eval.Eval(expr).(bool)
	if !ok {
		return false
	}
	return v
}

// MapValuer is a valuer that substitutes values for the mapped interface.
type MapValuer map[string]interface{}

// Value returns the value for a key in the MapValuer.
func (m MapValuer) Value(key string) (interface{}, bool) {
	v, ok := m[key]
	return v, ok
}

// Valuer is the interface that wraps the Value() method.
type Valuer interface {
	// Value returns the value and existence flag for a given key.
	Value(key string) (interface{}, bool)
}

// CallValuer implements the Call method for evaluating function calls.
type CallValuer interface {
	Valuer

	// Call is invoked to evaluate a function call (if possible).
	Call(name string, args []interface{}) (interface{}, bool)
}

// MultiValuer returns a Valuer that iterates over multiple Valuer instances
// to find a match.
func MultiValuer(valuers ...Valuer) Valuer {
	return multiValuer(valuers)
}

type multiValuer []Valuer

func (valuers multiValuer) Value(key string) (interface{}, bool) {
	for _, valuer := range valuers {
		if v, ok := valuer.Value(key); ok {
			return v, true
		}
	}
	return nil, false
}

func (valuers multiValuer) Call(name string, args []interface{}) (interface{}, bool) {
	for _, valuer := range valuers {
		if valuer, ok := valuer.(CallValuer); ok {
			if v, ok := valuer.Call(name, args); ok {
				return v, true
			}
		}
	}
	return nil, false
}

// ValuerEval will evaluate an expression using the Valuer.
type ValuerEval struct {
	Valuer Valuer

	// IntegerFloatDivision will set the eval system to treat
	// a division between two integers as a floating point division.
	IntegerFloatDivision bool
}

// Eval evaluates an expression and returns a value.
func (v *ValuerEval) Eval(expr Expr) interface{} {
	if expr == nil {
		return nil
	}

	switch expr := expr.(type) {
	case *BinaryExpr:
		return v.evalBinaryExpr(expr)
	case *NotExpr:
		switch exp := expr.Expr.(type) {
		case *BinaryExpr:
			v := v.evalBinaryExpr(exp)
			if v == nil {
				return nil
			}
			if val, ok := v.(bool); ok {
				return !val
			}
			return nil
		case *Function:
			if valuer, ok := v.Valuer.(CallValuer); ok {
				var args []interface{}

				if len(exp.Args) > 0 {
					args = make([]interface{}, len(exp.Args))

					for i := range exp.Args {
						// foreach function exhibits some corner cases.
						// Instead of evaluating the expression and storing
						// the value in the args slice, it operates on raw
						// binary and unary expressions.
						if exp.IsForeach() {
							switch {
							case exp.IsBinaryExprArg(i) || exp.IsNotExprArg(i) || exp.IsBareBoundVariableArg(i):
								args[i] = exp.Args[i]
							case exp.IsFieldArg(i):
								if i != 0 {
									field := exp.Args[i].(*FieldLiteral)
									// the final argument passed to the function is
									// a map with the key equal to the field name and
									// the value is the result of the map valuer access
									// in the outer context.
									args[i] = MapValuer{field.String(): v.Eval(field)}
								} else {
									// otherwise, this is the slice (iterable) argument
									args[i] = v.Eval(exp.Args[i])
								}
							}
						} else {
							args[i] = v.Eval(exp.Args[i])
						}
					}
				}

				value, _ := valuer.Call(exp.Name, args)
				if value == nil {
					return true
				}
				if val, ok := value.(bool); ok {
					return !val
				}
				return nil
			}
			return nil
		case *ParenExpr:
			v := v.Eval(exp.Expr)
			if v == nil {
				return nil
			}
			if val, ok := v.(bool); ok {
				return !val
			}
			return nil
		case *BoolLiteral:
			return !exp.Value
		default:
			return nil
		}
	case *IntegerLiteral:
		return expr.Value
	case *UnsignedLiteral:
		return expr.Value
	case *DecimalLiteral:
		return expr.Value
	case *ParenExpr:
		return v.Eval(expr.Expr)
	case *StringLiteral:
		return expr.Value
	case *ListLiteral:
		return expr.Values
	case *BoolLiteral:
		return expr.Value
	case *FieldLiteral:
		val, ok := v.Valuer.Value(expr.Value)
		if !ok {
			return nil
		}
		return val
	case *BoundFieldLiteral:
		val, ok := v.Valuer.Value(expr.Value)
		if !ok {
			return nil
		}
		return val
	case *BoundSegmentLiteral:
		val, ok := v.Valuer.Value(expr.Value)
		if !ok {
			return nil
		}
		return val
	case *BareBoundVariableLiteral:
		val, ok := v.Valuer.Value(expr.Value)
		if !ok {
			return nil
		}
		return val
	case *IPLiteral:
		return expr.Value
	case *Function:
		if valuer, ok := v.Valuer.(CallValuer); ok {
			var args []interface{}

			if len(expr.Args) > 0 {
				args = make([]interface{}, len(expr.Args))
				for i := range expr.Args {
					// foreach function exhibits some corner cases.
					// Instead of evaluating the expression and storing
					// the value in the args slice, it operates on raw
					// binary and unary expressions.
					if expr.IsForeach() {
						switch {
						case expr.IsBinaryExprArg(i) || expr.IsNotExprArg(i) || expr.IsBareBoundVariableArg(i):
							args[i] = expr.Args[i]
						case expr.IsFieldArg(i):
							if i != 0 {
								field := expr.Args[i].(*FieldLiteral)
								// the final argument passed to the function is
								// a map with the key equal to the field name and
								// the value is the result of the map valuer access
								// in the outer context.
								args[i] = MapValuer{field.String(): v.Eval(field)}
							} else {
								// otherwise, this is the slice (iterable) argument
								args[i] = v.Eval(expr.Args[i])
							}
						}
					} else {
						args[i] = v.Eval(expr.Args[i])
					}
				}
			}

			val, _ := valuer.Call(expr.Name, args)
			return val
		}
		return nil
	default:
		return nil
	}
}

func (v *ValuerEval) evalBinaryExpr(expr *BinaryExpr) interface{} {
	lhs := v.Eval(expr.LHS)
	// lazy evaluation for the AND/OR operators
	if lhs != nil && expr.Op == And {
		if val, ok := lhs.(bool); ok && !val {
			return false
		}
	}
	if lhs != nil && expr.Op == Or {
		if val, ok := lhs.(bool); ok && val {
			return true
		}
	}
	rhs := v.Eval(expr.RHS)
	if lhs == nil && rhs != nil {
		// when the LHS is nil and the RHS is a boolean, implicitly cast the
		// nil to false.
		if _, ok := rhs.(bool); ok {
			lhs = false
		}
	} else if lhs != nil && rhs == nil {
		// implicit cast of the RHS nil to false when the LHS is a boolean.
		if _, ok := lhs.(bool); ok {
			rhs = false
		}
	}
	// evaluate if both sides are simple types.
	switch lhs := lhs.(type) {
	case bool:
		rhs, ok := rhs.(bool)
		switch expr.Op {
		case And:
			return ok && (lhs && rhs)
		case Or:
			return ok && (lhs || rhs)
		case Eq:
			return ok && (lhs == rhs)
		case Neq:
			return ok && (lhs != rhs)
		}
	case int:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case Eq:
				return int64(lhs) == rhs
			case Neq:
				return int64(lhs) != rhs
			case Lt:
				return int64(lhs) < rhs
			case Lte:
				return int64(lhs) <= rhs
			case Gt:
				return int64(lhs) > rhs
			case Gte:
				return int64(lhs) >= rhs
			}
		case uint64:
			switch expr.Op {
			case Eq:
				return uint64(lhs) == rhs
			case Neq:
				return uint64(lhs) != rhs
			case Lt:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) < rhs
			case Lte:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) <= rhs
			case Gt:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) > rhs
			case Gte:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) >= rhs
			}
		case []uint16:
			switch expr.Op {
			case In:
				for _, i := range rhs {
					if int(i) == lhs {
						return true
					}
				}
				return false
			}
		}
	case uint8:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case Eq:
				return int64(lhs) == rhs
			case Neq:
				return int64(lhs) != rhs
			case Lt:
				return int64(lhs) < rhs
			case Lte:
				return int64(lhs) <= rhs
			case Gt:
				return int64(lhs) > rhs
			case Gte:
				return int64(lhs) >= rhs
			}
		case uint64:
			switch expr.Op {
			case Eq:
				return uint64(lhs) == rhs
			case Neq:
				return uint64(lhs) != rhs
			case Lt:
				return uint64(lhs) < rhs
			case Lte:
				return uint64(lhs) <= rhs
			case Gt:
				return uint64(lhs) > rhs
			case Gte:
				return uint64(lhs) >= rhs
			}
		}
	case float64:
		// try the rhs as a float64, int64, or uint64
		rhsf, ok := rhs.(float64)
		if !ok {
			switch val := rhs.(type) {
			case int64:
				rhsf, ok = float64(val), true
			case uint64:
				rhsf, ok = float64(val), true
			}
		}

		rhs := rhsf
		switch expr.Op {
		case Eq:
			return ok && (lhs == rhs)
		case Neq:
			return ok && (lhs != rhs)
		case Lt:
			return ok && (lhs < rhs)
		case Lte:
			return ok && (lhs <= rhs)
		case Gt:
			return ok && (lhs > rhs)
		case Gte:
			return ok && (lhs >= rhs)
		}
	case int64:
		// try as a float64 to see if a float cast is required.
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case uint64:
			switch expr.Op {
			case Eq:
				return uint64(lhs) == rhs
			case Neq:
				return uint64(lhs) != rhs
			case Lt:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) < rhs
			case Lte:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) <= rhs
			case Gt:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) > rhs
			case Gte:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) >= rhs
			}
		}
	case uint64:
		// try as a float64 to see if a float cast is required.
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case Eq:
				return lhs == uint64(rhs)
			case Neq:
				return lhs != uint64(rhs)
			case Lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint64(rhs)
			case Lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint64(rhs)
			case Gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint64(rhs)
			case Gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint64(rhs)
			}
		case uint64:
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		}
	case []uint64:
		switch rhs := rhs.(type) {
		case uint64:
			switch expr.Op {
			case Gt:
				for _, i := range lhs {
					if i > rhs {
						return true
					}
				}
				return false
			case Gte:
				for _, i := range lhs {
					if i >= rhs {
						return true
					}
				}
				return false
			}
		case int64:
			switch expr.Op {
			case Gt:
				for _, i := range lhs {
					if i > uint64(rhs) {
						return true
					}
				}
				return false
			case Gte:
				for _, i := range lhs {
					if i >= uint64(rhs) {
						return true
					}
				}
				return false
			}
		}
	case uint32:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int32:
			switch expr.Op {
			case Eq:
				return lhs == uint32(rhs)
			case Neq:
				return lhs != uint32(rhs)
			case Lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint32(rhs)
			case Lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint32(rhs)
			case Gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint32(rhs)
			case Gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint32(rhs)
			}
		case int64:
			switch expr.Op {
			case Eq:
				return lhs == uint32(rhs)
			case Neq:
				return lhs != uint32(rhs)
			case Lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint32(rhs)
			case Lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint32(rhs)
			case Gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint32(rhs)
			case Gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint32(rhs)
			}
		case uint32:
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case []string:
			switch expr.Op {
			case In:
				for _, s := range rhs {
					n, err := strconv.ParseUint(s, 10, 32)
					if err != nil {
						continue
					}
					if uint32(n) == lhs {
						return true
					}
				}
				return false
			}
		}
	case uint16:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case int32:
			switch expr.Op {
			case Eq:
				return lhs == uint16(rhs)
			case Neq:
				return lhs != uint16(rhs)
			case Lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint16(rhs)
			case Lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint16(rhs)
			case Gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint16(rhs)
			case Gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint16(rhs)
			}
		case int64:
			switch expr.Op {
			case Eq:
				return lhs == uint16(rhs)
			case Neq:
				return lhs != uint16(rhs)
			case Lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint16(rhs)
			case Lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint16(rhs)
			case Gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint16(rhs)
			case Gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint16(rhs)
			}
		case uint16:
			switch expr.Op {
			case Eq:
				return lhs == rhs
			case Neq:
				return lhs != rhs
			case Lt:
				return lhs < rhs
			case Lte:
				return lhs <= rhs
			case Gt:
				return lhs > rhs
			case Gte:
				return lhs >= rhs
			}
		case []string:
			switch expr.Op {
			case In:
				for _, s := range rhs {
					n, err := strconv.Atoi(s)
					if err != nil {
						continue
					}
					if uint16(n) == lhs {
						return true
					}
				}
				return false
			}
		}
	case string:
		switch expr.Op {
		case Eq:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return lhs == rhs
		case IEq:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return strings.EqualFold(lhs, rhs)
		case Neq:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return lhs != rhs
		case Contains:
			switch rhs := rhs.(type) {
			case string:
				return strings.Contains(lhs, rhs)
			case []string:
				for _, s := range rhs {
					if strings.Contains(lhs, s) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IContains:
			switch rhs := rhs.(type) {
			case string:
				return strings.Contains(strings.ToLower(lhs), strings.ToLower(rhs))
			case []string:
				for _, s := range rhs {
					if strings.Contains(strings.ToLower(lhs), strings.ToLower(s)) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case In:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, i := range rhs {
				if i == lhs {
					return true
				}
			}
			return false
		case IIn:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, i := range rhs {
				if strings.EqualFold(i, lhs) {
					return true
				}
			}
			return false
		case Startswith:
			switch rhs := rhs.(type) {
			case string:
				return strings.HasPrefix(lhs, rhs)
			case []string:
				for _, s := range rhs {
					if strings.HasPrefix(lhs, s) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IStartswith:
			switch rhs := rhs.(type) {
			case string:
				return strings.HasPrefix(strings.ToLower(lhs), strings.ToLower(rhs))
			case []string:
				for _, s := range rhs {
					if strings.HasPrefix(strings.ToLower(lhs), strings.ToLower(s)) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case Endswith:
			switch rhs := rhs.(type) {
			case string:
				return strings.HasSuffix(lhs, rhs)
			case []string:
				for _, s := range rhs {
					if strings.HasSuffix(lhs, s) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IEndswith:
			switch rhs := rhs.(type) {
			case string:
				return strings.HasSuffix(strings.ToLower(lhs), strings.ToLower(rhs))
			case []string:
				for _, s := range rhs {
					if strings.HasSuffix(strings.ToLower(lhs), strings.ToLower(s)) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case Matches:
			switch rhs := rhs.(type) {
			case string:
				return wildcard.Match(rhs, lhs)
			case []string:
				for _, pat := range rhs {
					if wildcard.Match(pat, lhs) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IMatches:
			switch rhs := rhs.(type) {
			case string:
				return wildcard.Match(strings.ToLower(rhs), strings.ToLower(lhs))
			case []string:
				for _, pat := range rhs {
					if wildcard.Match(strings.ToLower(pat), strings.ToLower(lhs)) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case Fuzzy:
			switch rhs := rhs.(type) {
			case string:
				return fuzzysearch.Match(rhs, lhs)
			case []string:
				for _, s := range rhs {
					if fuzzysearch.Match(s, lhs) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IFuzzy:
			switch rhs := rhs.(type) {
			case string:
				return fuzzysearch.MatchFold(rhs, lhs)
			case []string:
				for _, s := range rhs {
					if fuzzysearch.MatchFold(s, lhs) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case Fuzzynorm:
			switch rhs := rhs.(type) {
			case string:
				return fuzzysearch.MatchNormalized(rhs, lhs)
			case []string:
				for _, s := range rhs {
					if fuzzysearch.MatchNormalized(s, lhs) {
						return true
					}
				}
				return false
			default:
				return false
			}
		case IFuzzynorm:
			switch rhs := rhs.(type) {
			case string:
				return fuzzysearch.MatchNormalizedFold(rhs, lhs)
			case []string:
				for _, s := range rhs {
					if fuzzysearch.MatchNormalizedFold(s, lhs) {
						return true
					}
				}
				return false
			default:
				return false
			}
		}
	case net.IP:
		switch expr.Op {
		case Eq:
			rhs, ok := rhs.(net.IP)
			if !ok {
				return false
			}
			return lhs.Equal(rhs)
		case Neq:
			rhs, ok := rhs.(net.IP)
			if !ok {
				return false
			}
			return !lhs.Equal(rhs)
		case In:
			ips, ok := rhs.([]net.IP)
			if !ok {
				// keep backward compatibility with string lists
				addrs, ok := rhs.([]string)
				if !ok {
					return false
				}
				for _, s := range addrs {
					if net.ParseIP(s).Equal(lhs) {
						return true
					}
				}
				return false
			}
			for _, ip := range ips {
				if ip.Equal(lhs) {
					return true
				}
			}
			return false
		case Startswith:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return strings.HasPrefix(lhs.String(), rhs)
		case Endswith:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return strings.HasSuffix(lhs.String(), rhs)
		}
	case []string:
		switch expr.Op {
		case Contains:
			s, ok := rhs.(string)
			if !ok {
				rhs, ok := rhs.([]string)
				if !ok {
					return false
				}
				for _, s1 := range rhs {
					for _, s2 := range lhs {
						if strings.Contains(s2, s1) {
							return true
						}
					}
				}
				return false
			}
			for _, val := range lhs {
				if strings.Contains(val, s) {
					return true
				}
			}
			return false
		case IContains:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s1 := range lhs {
				for _, s2 := range rhs {
					if strings.Contains(strings.ToLower(s1), strings.ToLower(s2)) {
						return true
					}
				}
			}
			return false
		case In:
			s, ok := rhs.(string)
			if !ok {
				rhs, ok := rhs.([]string)
				if !ok {
					return false
				}
				for _, i := range lhs {
					for _, j := range rhs {
						if i == j {
							return true
						}
					}
				}
				return false
			}
			for _, val := range lhs {
				if val == s {
					return true
				}
			}
			return false
		case IIn:
			s, ok := rhs.(string)
			if !ok {
				rhs, ok := rhs.([]string)
				if !ok {
					return false
				}
				for _, i := range lhs {
					for _, j := range rhs {
						if strings.EqualFold(i, j) {
							return true
						}
					}
				}
			}
			for _, val := range lhs {
				if strings.EqualFold(val, s) {
					return true
				}
			}
			return false
		case Startswith:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s1 := range rhs {
				for _, s2 := range lhs {
					if strings.HasPrefix(s2, s1) {
						return true
					}
				}
			}
			return false
		case IStartswith:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s1 := range rhs {
				for _, s2 := range lhs {
					if strings.HasPrefix(strings.ToLower(s2), strings.ToLower(s1)) {
						return true
					}
				}
			}
			return false
		case Endswith:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s1 := range rhs {
				for _, s2 := range lhs {
					if strings.HasSuffix(s2, s1) {
						return true
					}
				}
			}
			return false
		case IEndswith:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s1 := range rhs {
				for _, s2 := range lhs {
					if strings.HasSuffix(strings.ToLower(s2), strings.ToLower(s1)) {
						return true
					}
				}
			}
			return false
		case Matches:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, pat := range rhs {
				for _, val := range lhs {
					if wildcard.Match(pat, val) {
						return true
					}
				}
			}
			return false
		case IMatches:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, pat := range rhs {
				for _, val := range lhs {
					if wildcard.Match(strings.ToLower(pat), strings.ToLower(val)) {
						return true
					}
				}
			}
			return false
		case Intersects:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			return len(sets.IntersectionStrings(lhs, rhs, false)) == len(rhs)
		case IIntersects:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			return len(sets.IntersectionStrings(lhs, rhs, true)) == len(rhs)
		}
	}

	// the types were not comparable. If our operation was an equality operation,
	// return false instead of true.
	switch expr.Op {
	case Eq, IEq, Neq, Lt, Lte, Gt, Gte:
		return false
	}
	return nil
}
