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
	"cmp"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// safely runs fn and reports whether it panicked. The evaluators read process
// state the synthetic events don't fully have, so some inputs are allowed to
// panic, and they are left out of the invariants.
func safely(fn func() any) (v any, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	return fn(), false
}

// assertEvaluatorInvariants checks, for every field and event, the properties
// every evaluator has to satisfy whatever the field is:
//   - an event the source of the field can't serve gives the default value
//   - the values an evaluator produces have one Go type, which is the one the
//     typed expression is compiled against
//   - an evaluator that has no value gives the default value
//
// The extractor has to be configured for all the fields.
func assertEvaluatorInvariants(t *testing.T, x *extractor, flds []Field, evts map[string]*event.Event) {
	t.Helper()
	for _, f := range flds {
		ev := x.evaluator(f)
		require.NotNil(t, ev, "%s has no evaluator", f.String())
		types := make(map[reflect.Type]string)
		for name, evt := range evts {
			got, panicked := safely(func() any { return x.Extract(f, evt) })
			if panicked {
				continue
			}
			if !servesEvent(f.Name.Source(), evt) {
				assert.Equal(t, defaultValue(f), got, "%s on %s: the source doesn't serve the event", f.String(), name)
				continue
			}
			ctx := &EvalCtx{Evt: evt, Resolvers: x.resolvers, peOpts: x.peOpts}
			v, panicked := safely(func() any { return ev.Eval(ctx) })
			if panicked {
				continue
			}
			if v == nil {
				assert.Equal(t, defaultValue(f), got, "%s on %s: no value", f.String(), name)
				continue
			}
			assert.True(t, reflect.DeepEqual(v, got), "%s on %s: the evaluator gives %#v, the extractor %#v", f.String(), name, v, got)
			if v != nil {
				types[reflect.TypeOf(v)] = name
			}
		}
		assert.LessOrEqual(t, len(types), 1, "%s produces values of different types: %v", f.String(), types)
	}
}

// evaluatedFields returns the fields of the source that have a typed evaluator.
func evaluatedFields(src fields.Source) []Field {
	var flds []Field
	for _, def := range fields.Get() {
		if def.Field.Source() == src && hasEvaluator(def.Field) {
			flds = append(flds, NewField(def.Field, string(def.Field), ""))
		}
	}
	slices.SortFunc(flds, func(a, b Field) int { return cmp.Compare(a.String(), b.String()) })
	return flds
}

func TestEvtEvaluatorsInvariants(t *testing.T) {
	flds := evaluatedFields(fields.SourceEvent)
	// the 21 evt.* fields of the event source, plus the kevt.* aliases
	// and the platform specific ones where they are declared
	require.GreaterOrEqual(t, len(flds), 21)

	cet := time.FixedZone("CET", 3600)
	named := func(ts time.Time) *event.Event {
		return &event.Event{
			Seq: 1<<40 + 7, PID: 1023, Tid: 2048, CPU: 3, Host: "kitty", Timestamp: ts,
			Params: event.ParamsOf(
				event.NewParam(params.Cmdline, params.String, params.Str("cmd.exe")),
				event.NewParam(params.ProcessName, params.String, params.Str("cmd.exe")),
			),
		}
	}
	evts := map[string]*event.Event{
		"zero":         {},
		"utc":          named(time.Date(2026, time.November, 24, 11, 31, 5, 123, time.UTC)),
		"cet":          named(time.Date(2026, time.March, 1, 0, 0, 0, 0, cet)),
		"leap day":     named(time.Date(2028, time.February, 29, 23, 59, 59, 999999999, time.UTC)),
		"week 53":      named(time.Date(2026, time.December, 31, 12, 0, 0, 0, time.UTC)),
		"before epoch": named(time.Date(1969, time.July, 20, 20, 17, 0, 0, time.UTC)),
		"no params":    {PID: 1, Timestamp: time.Date(2026, time.January, 1, 1, 1, 1, 1, time.UTC)},
	}

	// evt.arg is read with the name of a few parameters, present or not
	for _, arg := range []string{"cmdline", "pid", "port", "ts", "u64", "nope", ""} {
		flds = append(flds, NewField(fields.EvtArg, string(fields.EvtArg), arg))
	}
	for _, evt := range evts {
		evt.Params = append(evt.Params,
			event.NewParam("pid", params.PID, params.U32(7)),
			event.NewParam("port", params.Port, params.U16(443)),
			event.NewParam("u64", params.Uint64, params.U64(1<<40)),
			event.NewParam("ts", params.Time, params.Timestamp(evt.Timestamp)))
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}
