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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extractorWith returns the extractor for the field whose value is read by the
// given evaluator in place of the one of the field.
func extractorWith(f Field, ev Evaluator) *extractor {
	x := newExtractor(nil, nil, nil)
	x.fields = []boundField{newBoundField(f, ev)}
	x.evaluators.Store(f.String(), ev)
	return x
}

func TestEvaluatorEval(t *testing.T) {
	ev := &Uint32Evaluator{
		EvaluatorBase: EvaluatorBase{Field: "evt.test.pid"},
		Get: optional(func(e *event.Event) (uint32, bool) {
			return e.PID, e.PID != 0
		}),
	}
	var _ Evaluator = ev

	assert.Equal(t, uint32(1023), ev.Eval(&EvalCtx{Evt: &event.Event{PID: 1023}}))
	// no value is nil, and not the zero value of the type
	assert.Nil(t, ev.Eval(&EvalCtx{Evt: &event.Event{}}))

	assert.Equal(t, fields.Field("evt.test.pid"), ev.GetField())
	assert.False(t, ev.IsExpensive())

	// a value that is the zero value of the type is still a value
	host := &StringEvaluator{Get: always(func(e *event.Event) string { return e.Host })}
	v := host.Eval(&EvalCtx{Evt: &event.Event{}})
	assert.NotNil(t, v)
	assert.Equal(t, "", v)
}

func TestGetEvaluator(t *testing.T) {
	ev, err := GetEvaluator(Field{Name: fields.EvtPID, Value: "evt.pid"})
	require.NoError(t, err)
	assert.Equal(t, fields.EvtPID, ev.GetField())
	assert.IsType(t, &Uint32Evaluator{}, ev)
	assert.Equal(t, uint32(1023), ev.Eval(&EvalCtx{Evt: &event.Event{PID: 1023}}))

	_, err = GetEvaluator(Field{Name: "evt.test.unknown", Value: "evt.test.unknown"})
	assert.ErrorIs(t, err, ErrNoEvaluator)
	assert.False(t, hasEvaluator("evt.test.unknown"))
}

func TestGetEvaluatorBindsTheArgument(t *testing.T) {
	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	evt := &event.Event{Params: event.ParamsOf(str("cmdline", "a"), str("other", "b"))}

	// the evaluators of the same field with a different argument read different parameters
	a, err := GetEvaluator(NewField(fields.EvtArg, "evt.arg", "cmdline"))
	require.NoError(t, err)
	b, err := GetEvaluator(NewField(fields.EvtArg, "evt.arg", "other"))
	require.NoError(t, err)
	assert.Equal(t, "a", a.Eval(&EvalCtx{Evt: evt}))
	assert.Equal(t, "b", b.Eval(&EvalCtx{Evt: evt}))

	// no such parameter, no value
	none, err := GetEvaluator(NewField(fields.EvtArg, "evt.arg", "none"))
	require.NoError(t, err)
	assert.Nil(t, none.Eval(&EvalCtx{Evt: evt}))
}

func TestExtractorUsesTypedEvaluator(t *testing.T) {
	f := Field{Name: "evt.test.typed", Value: "evt.test.typed"}
	x := extractorWith(f, &Uint32Evaluator{EvaluatorBase: EvaluatorBase{Field: f.Name}, Get: optional(func(e *event.Event) (uint32, bool) {
		if e.Host != "kitty" {
			return 0, false
		}
		return e.PID, true
	})})

	// the value comes from the typed evaluator with its own type
	v := x.Extract(f, &event.Event{PID: 1023, Host: "kitty"})
	assert.Equal(t, uint32(1023), v)

	// no value means the default value of the field, as for every field
	v = x.Extract(f, &event.Event{PID: 1023, Host: "other"})
	assert.Equal(t, defaultValue(f), v)

	// and the values reach the valuer through the context
	ctx := &EvalCtx{Values: make(map[string]any)}
	x.extractAll(&event.Event{PID: 7, Host: "kitty"}, ctx)
	assert.Equal(t, uint32(7), ctx.Values["evt.test.typed"])
}

func TestEvaluatorOfUnservedSourceIsNeverRead(t *testing.T) {
	// a field of a source that serves no event is never read, not even by its evaluator
	f := Field{Name: "unknown.test.field", Value: "unknown.test.field"}
	x := extractorWith(f, &StringEvaluator{EvaluatorBase: EvaluatorBase{Field: f.Name}, Get: always(func(e *event.Event) string { return "boom" })})

	assert.Equal(t, defaultValue(f), x.Extract(f, &event.Event{}))
}

func TestExtractorCachesTheEvaluatorOfTheField(t *testing.T) {
	x := newExtractor(nil, nil, nil)
	f := NewField(fields.EvtPID, "evt.pid", "")
	assert.Equal(t, uint32(7), x.Extract(f, &event.Event{PID: 7}))
	assert.Same(t, x.evaluator(f), x.evaluator(f))

	// a field nobody reads has no evaluator, and the extractor remembers that
	none := Field{Name: "evt.test.unknown", Value: "evt.test.unknown"}
	assert.Nil(t, x.evaluator(none))
	assert.Nil(t, x.evaluator(none))
	assert.Equal(t, defaultValue(none), x.Extract(none, &event.Event{}))
}

// TestEvaluatorsAreConsistent checks every field of the platform that has an
// evaluator: it reads the field it is created for, and is flagged expensive
// as the field is.
func TestEvaluatorsAreConsistent(t *testing.T) {
	for _, def := range fields.Get() {
		t.Run(string(def.Field), func(t *testing.T) {
			f := NewField(def.Field, string(def.Field), "")
			if def.Argument != nil && !def.Argument.Optional {
				f = NewField(def.Field, string(def.Field), "1")
			}
			ev, err := GetEvaluator(f)
			if err != nil {
				assert.True(t, unserved[def.Field], "%s has no evaluator", def.Field)
				return
			}
			assert.Equal(t, def.Field, ev.GetField())
			assert.Equal(t, IsExpensive(def.Field), ev.IsExpensive())
			assert.NotEqual(t, fields.SourceNone, def.Field.Source())
		})
	}
}

func TestInterpolationLookupReadsTheEvaluator(t *testing.T) {
	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	evt := &event.Event{Params: event.ParamsOf(str("cmdline", "run"))}

	x := newExtractor(nil, nil, nil)
	assert.Equal(t, "run", x.lookup(NewField(fields.EvtArg, "evt.arg", "cmdline"), evt))
	// nothing is substituted for a missing value, unlike in the extraction
	assert.Nil(t, x.lookup(NewField(fields.EvtArg, "evt.arg", "none"), evt))
}
