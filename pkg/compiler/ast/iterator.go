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

package ast

import (
	"iter"
	"maps"
)

// IterableBinder adapts a concrete collection to a sequence of valuers, one per
// element. It returns false if it does not recognize the collection type.
// The yielded MapValuer may be reused between iterations.
type IterableBinder func(value any, b *Binding) (iter.Seq[MapValuer], bool)

// Iterator is the iteration engine behind the foreach function. It knows how to
// turn a collection into per-element valuers and how to evaluate a predicate
// against them.
//
// OS-specific collections are plugged in with Register, typically from init()
// functions.
type Iterator struct {
	binders []IterableBinder
}

// Binding describes what the predicate needs from every element. The name of
// the bound variable and the segments accessed on it.
type Binding struct {
	variable *BareBoundVariableLiteral
	segments []*BoundSegmentLiteral
}

// NewIterator returns an Iterator with the portable collections registered
// (strings, processes, memory mappings).
func NewIterator() *Iterator {
	it := &Iterator{}
	// it.Register(sliceBinder(bindString))
	// it.Register(sliceBinder(bindProcess))
	// it.Register(sliceBinder(bindMmap))
	return it
}

var DefaultIterator = NewIterator()

// RegisterIterable registers a collection adapter on the default iterator.
// Call it from init() only.
func RegisterIterable(fn IterableBinder) { DefaultIterator.Register(fn) }

// Register adds a collection adapter. Adapters are tried in registration order.
// Registration is not synchronized: do it before the iterator is used.
func (it *Iterator) Register(fn IterableBinder) {
	it.binders = append(it.binders, fn)
}

// Any reports whether the predicate holds for at least one element of the
// iterable. It returns false for unsupported collections or invalid predicates.
func (it *Iterator) Any(iterable any, variable *BareBoundVariableLiteral, predicate any, captures MapValuer) bool {
	pred, ok := newPredicate(predicate)
	if !ok {
		return false
	}
	seq, ok := it.resolve(iterable, &Binding{variable: variable, segments: pred.segments})
	if !ok {
		return false
	}
	return pred.AnyMatch(seq, captures)
}

func (it *Iterator) resolve(value any, b *Binding) (iter.Seq[MapValuer], bool) {
	for _, bind := range it.binders {
		if seq, ok := bind(value, b); ok {
			return seq, true
		}
	}
	return nil, false
}

// SliceBinder builds an IterableBinder for []T. The bind callback fills the
// cleared valuer with the values of the segments accessed by the predicate.
func SliceBinder[T any](bind func(b *Binding, item T, into MapValuer)) IterableBinder {
	return func(value any, b *Binding) (iter.Seq[MapValuer], bool) {
		items, ok := value.([]T)
		if !ok {
			return nil, false
		}
		return func(yield func(MapValuer) bool) {
			m := make(MapValuer, len(b.segments)+1)
			for _, item := range items {
				clear(m)
				bind(b, item, m)
				if !yield(m) {
					return
				}
			}
		}, true
	}
}

// bindString exposes a plain string as the bound variable itself.
func BindString(b *Binding, s string, into MapValuer) {
	into[b.variable.Value] = s
}

// // bindProcess exposes the portable process attributes. OS-specific attributes
// // are added by addPlatformProcessValues, defined per platform.
// func bindProcess(b *binding, proc *pstypes.PS, into MapValuer) {
// 	for _, seg := range b.segments {
// 		key := seg.Value
// 		switch seg.Segment {
// 		case fields.PIDSegment:
// 			into[key] = proc.PID
// 		case fields.NameSegment:
// 			into[key] = proc.Name
// 		case fields.ExeSegment:
// 			into[key] = proc.Exe
// 		case fields.CmdlineSegment:
// 			into[key] = proc.Cmdline
// 		case fields.ArgsSegment:
// 			into[key] = proc.Args
// 		case fields.CwdSegment:
// 			into[key] = proc.Cwd
// 		case fields.UsernameSegment:
// 			into[key] = proc.Username
// 		}
// 	}
// 	addPlatformProcessValues(b.segments, proc, into)
// }

// // bindMmap exposes memory mapping details.
// func bindMmap(b *binding, mmap pstypes.Mmap, into MapValuer) {
// 	for _, seg := range b.segments {
// 		key := seg.Value
// 		switch seg.Segment {
// 		case fields.AddressSegment:
// 			into[key] = mmap.BaseAddress.String()
// 		case fields.SizeSegment:
// 			into[key] = mmap.Size
// 		case fields.ProtectionSegment:
// 			into[key] = mmap.ProtectMask()
// 		case fields.TypeSegment:
// 			into[key] = mmap.Type
// 		case fields.PathSegment:
// 			into[key] = mmap.File
// 		}
// 	}
// }

// Predicate is the analyzed form of the expression evaluated per element.
type Predicate struct {
	expr          Expr
	segments      []*BoundSegmentLiteral // bound-variable segments referenced ($mod.path -> path)
	usesFunctions bool                   // expression calls functions, so a FunctionValuer is required
}

func newPredicate(e any) (*Predicate, bool) {
	expr, ok := e.(Expr)
	if !ok {
		return nil, false
	}
	switch expr.(type) {
	case *BinaryExpr, *NotExpr, *ParenExpr:
	default:
		return nil, false
	}

	p := &Predicate{expr: expr}
	WalkFunc(expr, func(n Node) {
		switch n := n.(type) {
		case *BoundSegmentLiteral:
			p.segments = append(p.segments, n)
		case *Function:
			p.usesFunctions = true
		}
	})
	return p, true
}

// AnyMatch reports whether the predicate holds for at least one element.
// The element valuer yielded by seq is only valid until the next iteration.
func (p *Predicate) AnyMatch(seq iter.Seq[MapValuer], captures MapValuer) bool {
	var calls MapValuer // scratch map shared across iterations, only needed with functions
	if p.usesFunctions {
		calls = make(MapValuer)
	}

	for elem := range seq {
		var valuers Valuer
		if p.usesFunctions {
			clear(calls)
			maps.Copy(calls, elem)
			maps.Copy(calls, captures)
			valuers = MultiValuer(FunctionValuer{calls}, elem, captures)
		} else {
			valuers = MultiValuer(elem, captures)
		}

		eval := ValuerEval{Valuer: valuers}
		if matched, _ := eval.Eval(p.expr, EvalOptions{}).(bool); matched {
			return true
		}
	}
	return false
}
