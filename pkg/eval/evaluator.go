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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// Evaluator is the interface of an evaluator. An evaluator reads the value of
// a single field from the event of the evaluation context, and GetEvaluator
// creates the one for a field.
//
// The interface is not generic, since GetEvaluator has to hand out the
// evaluator of any field, and the tree of evaluators holds them side by side.
// The Go type of the value is the one of the concrete evaluator, e.g. a
// StringEvaluator produces a string, so the declared type of the field and the
// type of the value can't disagree.
type Evaluator interface {
	// Eval returns the value of the field in the event of the context, or nil
	// if the field has no value for the event, e.g. the process state is
	// missing or the event is of an unrelated type. The value of a field is
	// never nil otherwise, since it is boxed with its type, so the nil only
	// means there is none.
	Eval(ctx *EvalCtx) any
	// GetField returns the field the evaluator reads.
	GetField() fields.Field
	// IsExpensive reports whether reading the field is costly, because it is
	// backed by a resolver, e.g. the signature store or the PE parser. The flag
	// is informative only.
	IsExpensive() bool
}

// EvaluatorBase holds what all the evaluators have in common. It is embedded
// by every evaluator.
type EvaluatorBase struct {
	// Field is the field the evaluator reads.
	Field fields.Field
	// Expensive flags the evaluators backed by a resolver.
	Expensive bool
}

// GetField returns the field the evaluator reads.
func (b *EvaluatorBase) GetField() fields.Field { return b.Field }

// IsExpensive reports whether reading the field is costly.
func (b *EvaluatorBase) IsExpensive() bool { return b.Expensive }

func (b *EvaluatorBase) base() *EvaluatorBase { return b }

// FieldEvaluator is the evaluator that reads a field of the type T. The
// evaluators of the common types have a name of their own, e.g. StringEvaluator,
// and the rest, e.g. the evaluator of the process modules, are used by their
// generic name. What they read is up to the Get function.
type FieldEvaluator[T any] struct {
	EvaluatorBase
	// Get returns the value of the field in the event of the context. The second
	// result is false if the field has no value for the event. An evaluator
	// that reads a field with an argument, e.g. ps.envs[winroot], has the
	// argument already, since it is created for the field as it is written in
	// the expression.
	Get func(*EvalCtx) (T, bool)
}

// Eval returns the value of the field, or nil if the field has no value.
func (e *FieldEvaluator[T]) Eval(ctx *EvalCtx) any {
	v, ok := e.Get(ctx)
	if !ok {
		return nil
	}
	return v
}

// The evaluators of the fields, by the type of the value they produce. The
// integer widths are the ones the fields have always been read with, e.g.
// Uint8Evaluator for evt.time.h.
type (
	StringEvaluator      = FieldEvaluator[string]
	BoolEvaluator        = FieldEvaluator[bool]
	Uint8Evaluator       = FieldEvaluator[uint8]
	Uint16Evaluator      = FieldEvaluator[uint16]
	Uint32Evaluator      = FieldEvaluator[uint32]
	Uint64Evaluator      = FieldEvaluator[uint64]
	Int64Evaluator       = FieldEvaluator[int64]
	StringSliceEvaluator = FieldEvaluator[[]string]
	IPEvaluator          = FieldEvaluator[net.IP]
	TimeEvaluator        = FieldEvaluator[time.Time]
	// AnyEvaluator reads the fields whose type depends on the argument or on
	// the event, e.g. evt.arg[name] or ps.envs.
	AnyEvaluator = FieldEvaluator[any]
)

// ErrNoEvaluator is returned for a field that nobody reads, so it always
// evaluates to the default value of its type.
var ErrNoEvaluator = errors.New("no evaluator")

// GetEvaluator returns the evaluator of the field. The field is the one
// written in the expression, so the evaluators of the fields with an argument
// have it. The evaluator is created for the field and isn't shared. If there
// is no evaluator, ErrNoEvaluator is returned.
func GetEvaluator(f Field) (Evaluator, error) {
	ev := evaluatorFor(f)
	if ev == nil {
		return nil, fmt.Errorf("%w for the %s field", ErrNoEvaluator, f.Name)
	}
	return ev, nil
}

// hasEvaluator reports whether the field has an evaluator.
func hasEvaluator(f fields.Field) bool {
	_, err := GetEvaluator(Field{Name: f, Value: string(f)})
	return err == nil
}

func evaluatorFor(f Field) Evaluator {
	// the deprecated kevt.* fields are read by the evaluator of their evt.*
	// counterpart. They only exist on Windows, so the field has to be declared
	if f.Name.IsKevtField() {
		if _, declared := fields.Lookup(f.Name); !declared {
			return nil
		}
		twin := f
		twin.Name = fields.Field(strings.TrimPrefix(string(f.Name), "k"))
		ev := evaluatorFor(twin)
		if ev == nil {
			return nil
		}
		ev.(interface{ base() *EvaluatorBase }).base().Field = f.Name
		return ev
	}
	ev := eventEvaluator(f)
	if ev == nil {
		ev = sharedProcessEvaluator(f)
	}
	if ev == nil {
		ev = platformEvaluator(f)
	}
	if ev == nil {
		return nil
	}
	ev.(interface{ base() *EvaluatorBase }).base().Expensive = IsExpensive(f.Name)
	return ev
}

// evaluatorBase returns the common part of the evaluator of the field.
func evaluatorBase(f Field) EvaluatorBase { return EvaluatorBase{Field: f.Name} }

// always adapts the function that reads a field that always has a value.
func always[T any](get func(*event.Event) T) func(*EvalCtx) (T, bool) {
	return func(ctx *EvalCtx) (T, bool) { return get(ctx.Evt), true }
}

// optional adapts the function that reads a field that may have no value.
func optional[T any](get func(*event.Event) (T, bool)) func(*EvalCtx) (T, bool) {
	return func(ctx *EvalCtx) (T, bool) { return get(ctx.Evt) }
}

// fromParam adapts the plain read of an event parameter, e.g.
//
//	&Int64Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromParam(params.FD, event.Params.GetInt64ByName)}
//
// is all there is to a field that is a parameter of the event. The value is the
// zero value if the event doesn't have the parameter.
func fromParam[T any](name string, get func(event.Params, string) T) func(*EvalCtx) (T, bool) {
	return always(func(e *event.Event) T { return param(e, name, get) })
}

// processOf tells the process whose state the field reads. A ps.* field is
// read from the process that generated the event, and a ps.parent.* field from
// its parent.
func processOf(f Field) func(*event.Event) *pstypes.PS {
	if strings.HasPrefix(string(f.Name), "ps.parent.") {
		return getParentPs
	}
	return func(e *event.Event) *pstypes.PS { return e.PS }
}

// fromPS adapts the function that reads a property of the process state. The
// field has no value if the process state isn't known.
func fromPS[T any](ps func(*event.Event) *pstypes.PS, get func(*pstypes.PS) T) func(*EvalCtx) (T, bool) {
	return func(ctx *EvalCtx) (T, bool) {
		p := ps(ctx.Evt)
		if p == nil {
			var zero T
			return zero, false
		}
		return get(p), true
	}
}

// The evaluators of the fields that are a plain read of the event parameter.

// stringParam reads the parameter in its string form, whatever its type is.
func stringParam(f Field, name string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.GetParamAsString(name) })}
}

func uint32Param(f Field, name string) Evaluator {
	return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromParam(name, event.Params.GetUint32ByName)}
}

func uint64Param(f Field, name string) Evaluator {
	return &Uint64Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromParam(name, event.Params.GetUint64ByName)}
}
