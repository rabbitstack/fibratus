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
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// extractor reads the values of the fields of a single expression from events.
//
// Every field is bound to its typed evaluator when the extractor is created,
// so nothing is looked up per event. What is still decided per event is whether
// the source of the field can serve the event at all, because that depends on
// the event itself: its category, the presence of the process state or the
// callstack. A field that has no evaluator, or whose source can't serve the
// event, evaluates to the default value of its type.
type extractor struct {
	// fields are the fields whose values come from the evaluated event, each
	// bound to its evaluator. Bound fields are skipped, since their values
	// originate from the events matched in the preceding sequence steps.
	fields []boundField
	// index maps the string form of the field, which is the key of its value
	// in the evaluation context, to the field.
	index map[string]*boundField
	// resolvers are handed to the evaluators through the context
	resolvers *Resolvers
	// peOpts are the PE directories the expression needs
	peOpts uint32
	// evaluators are the evaluators of the fields extracted on demand, e.g. the
	// ones of the bound variables, by the field as written in the expression.
	// An evaluator holds no state, so it is shared by all the goroutines.
	evaluators sync.Map
}

// boundField is the field together with its typed evaluator, if it has one.
type boundField struct {
	Field
	// key is the string form of the field, under which the value is
	// stored in the context
	key  string
	eval Evaluator
}

func newBoundField(f Field, ev Evaluator) boundField {
	return boundField{Field: f, key: f.String(), eval: ev}
}

// newExtractor creates the extractor for an expression that references
// the given fields and segments. The bound fields (e.g. $e1.ps.pe.imphash)
// only tell which data the expression needs, e.g. which PE directories to
// parse. They are never extracted eagerly from the evaluated event, because
// their values come from the events of the previous sequence steps through
// ExtractField.
func newExtractor(flds, bound []Field, segs []Segment) *extractor {
	configured := make(Fields, 0, len(flds)+len(bound))
	for _, f := range flds {
		configured.Add(f.Name, f.Value, f.Arg)
	}
	for _, f := range bound {
		configured.Add(f.Name, f.Value, f.Arg)
	}
	x := &extractor{resolvers: DefaultResolvers()}
	x.fields = make([]boundField, 0, len(flds))
	for _, f := range flds {
		// a field without an evaluator reads as the default value
		ev, _ := GetEvaluator(f)
		x.fields = append(x.fields, newBoundField(f, ev))
	}
	x.peOpts = peOptions(configured, segs)
	x.index = make(map[string]*boundField, len(x.fields))
	for i := range x.fields {
		x.index[x.fields[i].key] = &x.fields[i]
	}
	return x
}

// byKey returns the field whose value is stored under the key in the context,
// or nil if the extractor doesn't extract it, e.g. the bound variables.
func (x *extractor) byKey(key string) *boundField {
	return x.index[key]
}

// extractAll puts the values of all the unbound fields from the
// event into the context, so they are available before the evaluation.
func (x *extractor) extractAll(evt *event.Event, ctx *EvalCtx) {
	ctx.Evt = evt
	for i := range x.fields {
		ctx.put(&x.fields[i], x)
	}
}

// Extract returns the value of the field in the event. The value comes from
// the typed evaluator of the field, provided the source of the field can
// serve the event. Otherwise, or if there is no value, the default value for
// the field is returned.
func (x *extractor) Extract(f Field, evt *event.Event) any {
	// the evaluators only read the event of the context, and the
	// context isn't used afterwards, so it doesn't have to be pooled
	ctx := EvalCtx{Evt: evt}
	return x.extract(f, x.evaluator(f), &ctx)
}

// evaluator returns the evaluator of the field, or nil if there is none. It is
// created the first time the field is asked for.
func (x *extractor) evaluator(f Field) Evaluator {
	key := f.String()
	if ev, ok := x.evaluators.Load(key); ok {
		if ev == noEval {
			return nil
		}
		return ev.(Evaluator)
	}
	ev, _ := GetEvaluator(f)
	if ev == nil {
		x.evaluators.Store(key, noEval)
		return nil
	}
	x.evaluators.Store(key, ev)
	return ev
}

// noEval marks a field that has no evaluator in the cache of the extractor.
var noEval Evaluator = &noEvaluator{}

type noEvaluator struct{ EvaluatorBase }

func (*noEvaluator) Eval(*EvalCtx) any { return nil }

func (x *extractor) extract(f Field, ev Evaluator, ctx *EvalCtx) any {
	ctx.Resolvers = x.resolvers
	ctx.peOpts = x.peOpts
	if ev != nil && servesEvent(f.Name.Source(), ctx.Evt) {
		if v := ev.Eval(ctx); v != nil {
			return v
		}
	}
	return defaultValue(f)
}

// lookup returns the value of the field in the event, or nil if the field has
// none. In contrast to Extract, it doesn't substitute the default value, and it
// doesn't ask the gate if the source can serve the event. The caller is only
// interested in what the evaluator really has.
func (x *extractor) lookup(f Field, evt *event.Event) any {
	ev := x.evaluator(f)
	if ev == nil {
		return nil
	}
	ctx := EvalCtx{Evt: evt, Resolvers: x.resolvers, peOpts: x.peOpts}
	return ev.Eval(&ctx)
}
