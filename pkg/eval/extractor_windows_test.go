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
	"strings"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func syntheticEvents() map[string]*event.Event {
	ps := &pstypes.PS{
		PID:     1023,
		Ppid:    345,
		Name:    "cmd.exe",
		Cmdline: `cmd.exe /c whoami`,
		SID:     `LOCAL\tor`,
		Parent:  &pstypes.PS{PID: 345, Name: "explorer.exe"},
	}
	withPS := func(typ event.Type) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Tid: 2048, Host: "kitty", PS: ps}
	}
	return map[string]*event.Event{
		"empty":        {},
		"createproc":   withPS(event.CreateProcess),
		"createthread": withPS(event.CreateThread),
		"createfile":   withPS(event.CreateFile),
		"regsetvalue":  withPS(event.RegSetValue),
		"connect":      withPS(event.Connect),
		"querydns":     withPS(event.QueryDNS),
		"virtualalloc": withPS(event.VirtualAlloc),
		"loadmodule":   withPS(event.LoadModule),
		"no ps":        {Type: event.CreateFile, PID: 1023, Params: event.ParamsOf(event.NewParam(params.FilePath, params.String, params.Str(`C:\a.dll`)))},
	}
}

func TestBoundExtractionMatchesTrialExtraction(t *testing.T) {
	var flds []Field
	for _, fi := range fields.Get() {
		f := Field{Name: fi.Field, Value: string(fi.Field)}
		// fields with an argument need a valid one
		if fi.Argument != nil {
			switch fi.Field {
			case fields.EvtArg, fields.KevtArg:
				f.Arg = "cmdline"
			case fields.PsAncestor:
				f.Arg = "1"
			default:
				if !fi.Argument.Optional {
					continue
				}
			}
		}
		flds = append(flds, f)
	}
	require.Greater(t, len(flds), 100)

	// the extractor is configured for all the fields, as the broadest rule would
	x := newExtractor(flds, nil, nil)

	assertEvaluatorInvariants(t, x, flds, syntheticEvents())
}

func TestPEFieldsAreBoundToTheirEvaluators(t *testing.T) {
	prog, err := NewProgram("pe", `ps.pe.imphash = 'x' and ps.signature.trusted = true and ps.name = 'cmd.exe'`)
	require.NoError(t, err)

	require.Len(t, prog.extractor.fields, 3)
	for _, f := range prog.extractor.fields {
		assert.NotNil(t, f.eval, f.String())
	}
}

// TestBoundPEFieldConfiguresPEOptions checks that the PE directories to
// parse are learned from a PE field referenced only through a bound variable.
func TestBoundPEFieldConfiguresPEOptions(t *testing.T) {
	prog, err := NewProgram("bound.pe", `sequence
	|evt.name = 'CreateProcess'| as e1
	|evt.name = 'CreateFile' and ps.sid = $e1.ps.pe.imphash|`)
	require.NoError(t, err)

	require.Len(t, prog.GetBoundFields(), 1)
	assert.Equal(t, "ps.pe.imphash", prog.GetBoundFields()[0].String())

	assert.NotEqual(t, uint32(0), prog.extractor.peOpts&uint32(PEImphash), "the imphash is needed")

	// the field is configured, but not extracted from the evaluated event
	for _, f := range prog.extractor.fields {
		assert.NotEqual(t, "ps.pe.imphash", f.String())
	}
}

// TestDeprecatedEventFieldsAreReadLikeTheirCounterparts checks that every
// kevt.* field is read by an evaluator that gives the value of its evt.*
// counterpart, but still reads the field it was created for.
func TestDeprecatedEventFieldsAreReadLikeTheirCounterparts(t *testing.T) {
	evt := &event.Event{PID: 1023, Tid: 2048, Host: "kitty", Timestamp: time.Date(2026, time.November, 24, 11, 31, 5, 0, time.UTC)}
	var n int
	for _, def := range fields.Get() {
		kevt := def.Field
		if !kevt.IsKevtField() || kevt == fields.KevtArg {
			continue
		}
		name := fields.Field(strings.TrimPrefix(string(kevt), "k"))
		if name.Source() != fields.SourceEvent {
			continue
		}
		k, err := GetEvaluator(NewField(kevt, string(kevt), ""))
		require.NoError(t, err, kevt)
		e, err := GetEvaluator(NewField(name, string(name), ""))
		require.NoError(t, err, name)
		assert.Equal(t, kevt, k.GetField())
		assert.Equal(t, name, e.GetField())
		assert.Equal(t, e.Eval(&EvalCtx{Evt: evt}), k.Eval(&EvalCtx{Evt: evt}), kevt)
		n++
	}
	assert.GreaterOrEqual(t, n, 20)
}
