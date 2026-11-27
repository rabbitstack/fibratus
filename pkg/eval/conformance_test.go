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
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evaluateField returns the value the evaluator of the field gives for the
// event, and false if the field has no evaluator or the evaluator has no value.
func evaluateField(f Field, evt *event.Event) (any, bool) {
	ev, err := GetEvaluator(f)
	if err != nil {
		return nil, false
	}
	v := ev.Eval(&EvalCtx{Evt: evt})
	return v, v != nil
}

// declaredGoType returns the Go type an evaluator has to return for a field
// whose declared type is typ. The second result is false if the declared
// type has no single Go counterpart, e.g. the flags and the variants.
func declaredGoType(typ params.Type) (reflect.Type, bool) {
	switch typ {
	case params.Uint8:
		return reflect.TypeFor[uint8](), true
	case params.Uint16, params.Port:
		return reflect.TypeFor[uint16](), true
	case params.Uint32, params.PID, params.TID:
		return reflect.TypeFor[uint32](), true
	case params.Uint64:
		return reflect.TypeFor[uint64](), true
	case params.Int8:
		return reflect.TypeFor[int8](), true
	case params.Int16:
		return reflect.TypeFor[int16](), true
	case params.Int32:
		return reflect.TypeFor[int32](), true
	case params.Int64:
		return reflect.TypeFor[int64](), true
	case params.Float:
		return reflect.TypeFor[float32](), true
	case params.Double:
		return reflect.TypeFor[float64](), true
	case params.Bool:
		return reflect.TypeFor[bool](), true
	case params.String:
		return reflect.TypeFor[string](), true
	case params.Time:
		return reflect.TypeFor[time.Time](), true
	case params.IP, params.IPv4, params.IPv6:
		return reflect.TypeFor[net.IP](), true
	case params.Binary:
		return reflect.TypeFor[[]byte](), true
	case params.Slice:
		return reflect.TypeFor[[]string](), true
	}
	return nil, false
}

// TestEvtEvaluatorsReturnDeclaredTypes checks that the dynamic type of the value
// the event evaluators return is the type the field is declared with.
// The declared type decides the default value of the field, so a disagreement
// makes the fallback value incomparable with the value the evaluator produces.
func TestEvtEvaluatorsReturnDeclaredTypes(t *testing.T) {
	evt := &event.Event{
		Seq:       42,
		PID:       1023,
		Tid:       2048,
		CPU:       2,
		Host:      "kitty",
		Timestamp: time.Date(2026, time.November, 24, 11, 31, 5, 123, time.UTC),
		Params: event.ParamsOf(
			event.NewParam(params.Cmdline, params.String, params.Str("cmd.exe")),
		),
	}

	// the name, category and description come from the event type
	// metadata, while evt.arg is a variant. Neither has a fixed type
	skipped := map[fields.Field]struct{}{
		fields.EvtName:     {},
		fields.EvtCategory: {},
		fields.EvtDesc:     {},
		fields.EvtArg:      {},
	}

	var checked atomic.Int32
	for _, fi := range fields.Get() {
		if !fi.Field.IsEvtField() {
			continue
		}
		if _, ok := skipped[fi.Field]; ok {
			continue
		}
		t.Run(string(fi.Field), func(t *testing.T) {
			v, ok := evaluateField(Field{Name: fi.Field, Value: string(fi.Field)}, evt)
			if !ok {
				// e.g. evt.retval or evt.is_direct_syscall on the other platform
				t.Skipf("%s has no value for the event", fi.Field)
			}

			want, ok := declaredGoType(fi.Type)
			if !ok {
				t.Skipf("declared type %v has no single Go type", fi.Type)
			}
			assert.Equal(t, want, reflect.TypeOf(v),
				"%s is declared as %v, but the evaluator returns %T", fi.Field, fi.Type, v)
			checked.Add(1)
		})
	}
	// guards against the loop silently skipping everything
	assert.Greater(t, int(checked.Load()), 10)
}

func TestEvtEvaluatorTimeAndParamValues(t *testing.T) {
	evt := &event.Event{
		Timestamp: time.Date(2026, time.November, 24, 11, 31, 5, 123, time.UTC),
		Params: event.ParamsOf(
			event.NewParam(params.Cmdline, params.String, params.Str("cmd.exe")),
		),
	}

	var tests = []struct {
		field fields.Field
		value any
	}{
		{fields.EvtTimeHour, uint8(11)},
		{fields.EvtTimeMin, uint8(31)},
		{fields.EvtTimeSec, uint8(5)},
		{fields.EvtDateDay, uint8(24)},
		{fields.EvtDateMonth, uint8(11)},
		{fields.EvtTime, "11:31:05"},
		{fields.EvtDate, "2026-11-24"},
		{fields.EvtNparams, uint64(1)},
	}
	for _, tt := range tests {
		t.Run(string(tt.field), func(t *testing.T) {
			v, ok := evaluateField(Field{Name: tt.field, Value: string(tt.field)}, evt)
			require.True(t, ok)
			assert.Equal(t, tt.value, v)

			// the default value has to be comparable with the produced one
			want, ok := declaredGoType(tt.field.Type())
			require.True(t, ok)
			assert.Equal(t, want, reflect.TypeOf(tt.value))
		})
	}
}
