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
	"fmt"
	"iter"
	"slices"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// ForeachEvaluator evaluates the foreach function, which adds the iteration to the
// rule language. The first argument is the collection, typically yielded by the
// pseudo field, e.g. the process modules, threads, memory mappings or the stack
// frames of the thread. It is also possible to iterate over a plain slice of
// strings. The second argument is the variable bound to every element of the
// collection, and the third argument is the predicate, which accesses the
// element through the variable, usually followed by the segment that denotes the
// attribute of the element. The predicate is evaluated for every element, and the
// function is true if the predicate holds for any of them.
//
// The function doesn't take the value of its predicate as an argument. The
// predicate is compiled once as the evaluator, like the rest of the expression,
// and the variable is bound by writing the attributes of the element the
// predicate reads into the context before it is evaluated. This is why the
// evaluator doesn't evaluate the predicate to a value, but runs it.
//
// The fields from the outer context, such as ps.is_protected, are read from the
// event of the context like anywhere else, so listing them as the optional
// arguments of the function, which is required for the sake of the readers of
// the rule, doesn't change how the predicate is evaluated.
//
// Some examples:
//
//   - Traverses process modules and return true if the module path matches the pattern
//     foreach(ps._modules, $mod, $mod.path imatches '?:\\Windows\\System32\\us?r32.dll')
//
//   - For each process ancestor, checks if the ancestor is services.exe and the current process is protected
//     foreach(ps._ancestors, $proc, $proc.name = 'services.exe' and ps.is_protected, ps.is_protected)
type ForeachEvaluator struct {
	EvaluatorBase
	// Iterable evaluates to the collection.
	Iterable Evaluator
	// Variable is the bound variable as written in the expression, e.g. $mod.
	Variable string
	// Predicate is evaluated for every element.
	Predicate Evaluator
	// Segments are the attributes of the element the predicate reads.
	Segments []*ast.BoundSegmentLiteral
}

func newForeach(expr *ast.Function, x *extractor) (Evaluator, error) {
	if len(expr.Args) < 3 {
		return nil, fmt.Errorf("foreach function requires 3 argument(s) but %d argument(s) given", len(expr.Args))
	}
	v, ok := expr.Args[1].(*ast.BareBoundVariableLiteral)
	if !ok {
		return nil, fmt.Errorf("the second argument of the foreach function is not a bound variable")
	}
	e := &ForeachEvaluator{
		Iterable:  compileNode(expr.Args[0], x),
		Variable:  v.Value,
		Predicate: compileNode(expr.Args[2], x),
	}
	ast.WalkFunc(expr.Args[2], func(n ast.Node) {
		if seg, ok := n.(*ast.BoundSegmentLiteral); ok {
			e.Segments = append(e.Segments, seg)
		}
	})
	return e, nil
}

func (e *ForeachEvaluator) Eval(ctx *EvalCtx) any {
	collection := e.Iterable.Eval(ctx)
	if collection == nil {
		return false
	}
	// the values of the element must not outlive the loop, since the
	// context is shared with the rest of the rules
	defer e.unbind(ctx)

	switch items := collection.(type) {
	case []string:
		return loop(e, ctx, slices.Values(items), bindString)
	case []*pstypes.PS:
		return loop(e, ctx, slices.Values(items), bindProcess)
	case []pstypes.Mmap:
		return loop(e, ctx, slices.Values(items), bindMmap)
	}
	return e.eachPlatform(ctx, collection)
}

// binding is what a bind function writes the attributes of the element into.
type binding struct {
	values   map[string]any
	variable string
	segments []*ast.BoundSegmentLiteral
}

// loop evaluates the predicate for the elements of the collection until it holds.
func loop[T any](e *ForeachEvaluator, ctx *EvalCtx, items iter.Seq[T], bind func(*binding, T)) bool {
	b := &binding{values: ctx.Values, variable: e.Variable, segments: e.Segments}
	for item := range items {
		e.unbind(ctx)
		bind(b, item)
		if matched, _ := e.Predicate.Eval(ctx).(bool); matched {
			return true
		}
	}
	return false
}

// unbind removes the values of the bound element from the context.
func (e *ForeachEvaluator) unbind(ctx *EvalCtx) {
	delete(ctx.Values, e.Variable)
	for _, seg := range e.Segments {
		delete(ctx.Values, seg.Value)
	}
}

// bindString exposes the string as the bound variable itself.
func bindString(b *binding, s string) {
	b.values[b.variable] = s
}

// bindProcess exposes the process attributes.
func bindProcess(b *binding, proc *pstypes.PS) {
	for _, seg := range b.segments {
		key := seg.Value
		switch seg.Segment {
		case fields.PIDSegment:
			b.values[key] = proc.PID
		case fields.NameSegment:
			b.values[key] = proc.Name
		case fields.ExeSegment:
			b.values[key] = proc.Exe
		case fields.CmdlineSegment:
			b.values[key] = proc.Cmdline
		case fields.ArgsSegment:
			b.values[key] = proc.Args
		case fields.CwdSegment:
			b.values[key] = proc.Cwd
		case fields.UsernameSegment:
			b.values[key] = proc.Username
		}
	}
	bindPlatformProcess(b, proc)
}

// bindMmap exposes the memory mapping details.
func bindMmap(b *binding, mmap pstypes.Mmap) {
	for _, seg := range b.segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			b.values[key] = mmap.BaseAddress.String()
		case fields.SizeSegment:
			b.values[key] = mmap.Size
		case fields.ProtectionSegment:
			b.values[key] = mmap.ProtectMask()
		case fields.TypeSegment:
			b.values[key] = mmap.Type
		case fields.PathSegment:
			b.values[key] = mmap.File
		}
	}
}
