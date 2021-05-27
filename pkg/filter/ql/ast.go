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
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	"net"
	"strings"
)

// Eval evaluates expr against a map that contains the field values.
func Eval(expr Expr, m map[string]interface{}, multivaluer bool) bool {
	var eval ValuerEval
	if multivaluer {
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
		switch expr1 := expr.Expr.(type) {
		case *BinaryExpr:
			v := v.evalBinaryExpr(expr1)
			if v == nil {
				return nil
			}
			if val, ok := v.(bool); ok {
				return !val
			}
			return nil
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
	case *IPLiteral:
		return expr.Value
	case *Function:
		if valuer, ok := v.Valuer.(CallValuer); ok {
			var args []interface{}
			if len(expr.Args) > 0 {
				args = make([]interface{}, len(expr.Args))
				for i := range expr.Args {
					args[i] = v.Eval(expr.Args[i])
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
		case and:
			return ok && (lhs && rhs)
		case or:
			return ok && (lhs || rhs)
		case eq:
			return ok && (lhs == rhs)
		case neq:
			return ok && (lhs != rhs)
		}
	case int:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case eq:
				return int64(lhs) == rhs
			case neq:
				return int64(lhs) != rhs
			case lt:
				return int64(lhs) < rhs
			case lte:
				return int64(lhs) <= rhs
			case gt:
				return int64(lhs) > rhs
			case gte:
				return int64(lhs) >= rhs
			}
		case uint64:
			switch expr.Op {
			case eq:
				return uint64(lhs) == rhs
			case neq:
				return uint64(lhs) != rhs
			case lt:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) < rhs
			case lte:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) <= rhs
			case gt:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) > rhs
			case gte:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) >= rhs
			}
		}
	case uint8:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case eq:
				return int64(lhs) == rhs
			case neq:
				return int64(lhs) != rhs
			case lt:
				return int64(lhs) < rhs
			case lte:
				return int64(lhs) <= rhs
			case gt:
				return int64(lhs) > rhs
			case gte:
				return int64(lhs) >= rhs
			}
		case uint64:
			switch expr.Op {
			case eq:
				return uint64(lhs) == rhs
			case neq:
				return uint64(lhs) != rhs
			case lt:
				return uint64(lhs) < rhs
			case lte:
				return uint64(lhs) <= rhs
			case gt:
				return uint64(lhs) > rhs
			case gte:
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
		case eq:
			return ok && (lhs == rhs)
		case neq:
			return ok && (lhs != rhs)
		case lt:
			return ok && (lhs < rhs)
		case lte:
			return ok && (lhs <= rhs)
		case gt:
			return ok && (lhs > rhs)
		case gte:
			return ok && (lhs >= rhs)
		}
	case int64:
		// try as a float64 to see if a float cast is required.
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case uint64:
			switch expr.Op {
			case eq:
				return uint64(lhs) == rhs
			case neq:
				return uint64(lhs) != rhs
			case lt:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) < rhs
			case lte:
				if lhs < 0 {
					return true
				}
				return uint64(lhs) <= rhs
			case gt:
				if lhs < 0 {
					return false
				}
				return uint64(lhs) > rhs
			case gte:
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
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int64:
			switch expr.Op {
			case eq:
				return lhs == uint64(rhs)
			case neq:
				return lhs != uint64(rhs)
			case lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint64(rhs)
			case lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint64(rhs)
			case gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint64(rhs)
			case gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint64(rhs)
			}
		case uint64:
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		}
	case uint32:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int32:
			switch expr.Op {
			case eq:
				return lhs == uint32(rhs)
			case neq:
				return lhs != uint32(rhs)
			case lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint32(rhs)
			case lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint32(rhs)
			case gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint32(rhs)
			case gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint32(rhs)
			}
		case int64:
			switch expr.Op {
			case eq:
				return lhs == uint32(rhs)
			case neq:
				return lhs != uint32(rhs)
			case lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint32(rhs)
			case lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint32(rhs)
			case gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint32(rhs)
			case gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint32(rhs)
			}
		case uint32:
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		}
	case uint16:
		switch rhs := rhs.(type) {
		case float64:
			lhs := float64(lhs)
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		case int32:
			switch expr.Op {
			case eq:
				return lhs == uint16(rhs)
			case neq:
				return lhs != uint16(rhs)
			case lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint16(rhs)
			case lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint16(rhs)
			case gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint16(rhs)
			case gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint16(rhs)
			}
		case int64:
			switch expr.Op {
			case eq:
				return lhs == uint16(rhs)
			case neq:
				return lhs != uint16(rhs)
			case lt:
				if rhs < 0 {
					return false
				}
				return lhs < uint16(rhs)
			case lte:
				if rhs < 0 {
					return false
				}
				return lhs <= uint16(rhs)
			case gt:
				if rhs < 0 {
					return true
				}
				return lhs > uint16(rhs)
			case gte:
				if rhs < 0 {
					return true
				}
				return lhs >= uint16(rhs)
			}
		case uint16:
			switch expr.Op {
			case eq:
				return lhs == rhs
			case neq:
				return lhs != rhs
			case lt:
				return lhs < rhs
			case lte:
				return lhs <= rhs
			case gt:
				return lhs > rhs
			case gte:
				return lhs >= rhs
			}
		}
	case string:
		switch expr.Op {
		case eq:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return lhs == rhs
		case neq:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			return lhs != rhs
		case contains:
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
		case icontains:
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
		case in:
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
		case startswith:
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
		case endswith:
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
		case matches:
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
		case imatches:
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
		case fuzzy:
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
		case ifuzzy:
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
		case fuzzynorm:
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
		case ifuzzynorm:
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
		case eq:
			rhs, ok := rhs.(net.IP)
			if !ok {
				return false
			}
			return lhs.Equal(rhs)
		case neq:
			rhs, ok := rhs.(net.IP)
			if !ok {
				return false
			}
			return !lhs.Equal(rhs)
		case in:
			rhs, ok := rhs.([]string)
			if !ok {
				return false
			}
			for _, s := range rhs {
				if net.ParseIP(s).Equal(lhs) {
					return true
				}
			}
			return false
		}
	case []string:
		switch expr.Op {
		case contains:
			rhs, ok := rhs.(string)
			if !ok {
				return false
			}
			for _, s := range lhs {
				if s == rhs {
					return true
				}
			}
			return false
		case in:
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
		case matches:
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
		case imatches:
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
		}
	}

	// the types were not comparable. If our operation was an equality operation,
	// return false instead of true.
	switch expr.Op {
	case eq, neq, lt, lte, gt, gte:
		return false
	}
	return nil
}
