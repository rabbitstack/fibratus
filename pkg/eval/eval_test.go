/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

	"github.com/google/uuid"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/macro"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkSequenceExpr(t *testing.T) {
	var tests = []struct {
		expression string
		assertions func(*testing.T, *Evaluator)
	}{
		{`sequence 
	maxspan 2s
	by ps.uuid
	|evt.name = 'CreateProcess'|
	|evt.name = 'CreateFile'|`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 2)
		}},
		{`sequence 
	maxspan 2s
	by ps.uuid, file.object
	|evt.name = 'CreateProcess' and ps.name = 'explorer.exe'|
	|evt.name = 'CreateFile'|`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 4)
		}},
		{`sequence 
	maxspan 2s
	|evt.name = 'CreateProcess'| by ps.exe
	|evt.name = 'CreateFile'| by file.path`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 3)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			eval, err := NewEvaluator(uuid.New().String(), tt.expression)
			require.NoError(t, err)
			tt.assertions(t, eval)
		})
	}
}

func fieldNames(e *Evaluator) []string {
	names := make([]string, 0)
	for _, f := range e.GetFields() {
		names = append(names, f.String())
	}
	return names
}

func TestFieldsAreUnique(t *testing.T) {
	f := NewFields()
	f.Add(Field{Name: fields.PsName, Value: "ps.name"})
	f.Add(Field{Name: fields.PsName, Value: "ps.name"})
	f.Add(Field{Name: fields.PsName, Value: "ps.name"}, Field{Name: fields.FileName, Value: "file.name"})
	// the same field bound to a different aliases is a distinct field
	f.Add(Field{Name: fields.PsName, Value: "$e1.ps.name", BoundVar: "e1"})
	f.Add(Field{Name: fields.PsName, Value: "$e1.ps.name", BoundVar: "e1"})
	f.Add(Field{Name: fields.PsName, Value: "$e2.ps.name", BoundVar: "e2"})
	// fields with arguments are distinct from fields without
	f.Add(Field{Name: fields.EvtArg, Value: "evt.arg", Arg: "cmdline"}, Field{Name: fields.EvtArg, Value: "evt.arg", Arg: "exe"})

	assert.Len(t, f.List(), 6)

	// the zero value is usable
	var zero Fields
	zero.Add(Field{Name: fields.PsName, Value: "ps.name"})
	assert.Len(t, zero.List(), 1)
}

func TestExtractToValuerSkipsBoundFields(t *testing.T) {
	f := NewFields()
	f.Add(
		Field{Name: fields.PsName, Value: "ps.name"},
		Field{Name: fields.PsName, Value: "$e1.ps.name", BoundVar: "e1"},
	)

	evt := testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1024, "cmd.exe")))

	valuer := AcquireValuerCache()
	defer valuer.Release()

	f.ExtractToValuer(evt, valuer)

	assert.Equal(t, "cmd.exe", valuer.Valuer["ps.name"])
	_, ok := valuer.Valuer["$e1.ps.name"]
	assert.False(t, ok)
}

func TestEvaluatorEval(t *testing.T) {
	var tests = []struct {
		name     string
		expr     string
		evt      *event.Event
		expected bool
	}{
		{
			"match",
			"evt.name = 'CreateProcess' and ps.name = 'cmd.exe'",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "cmd.exe"))),
			true,
		},
		{
			"process name mismatch",
			"evt.name = 'CreateProcess' and ps.name = 'cmd.exe'",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "pwsh.exe"))),
			false,
		},
		{
			"event name mismatch",
			"evt.name = 'CreateProcess' and ps.name = 'cmd.exe'",
			testutil.MakeEvent(event.CreateFile, testutil.WithPS(testutil.MakePS(1, "cmd.exe"))),
			false,
		},
		{
			"list operand",
			"evt.name = 'CreateProcess' and ps.name in ('cmd.exe', 'pwsh.exe')",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "pwsh.exe"))),
			true,
		},
		{
			"negation",
			"evt.name = 'CreateProcess' and ps.name != 'cmd.exe'",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "pwsh.exe"))),
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := NewEvaluator(uuid.New().String(), tt.expr)
			require.NoError(t, err)

			valuer := AcquireValuerCache()
			defer valuer.Release()
			assert.Equal(t, tt.expected, ev.Eval(tt.evt, valuer))
		})
	}
}

func TestEvaluatorWithMacros(t *testing.T) {
	store, err := macro.NewStore(
		&policy.MacroDef{ID: "spawn_process", Expression: "evt.name = 'CreateProcess'"},
		&policy.MacroDef{ID: "shells", Values: []string{"cmd.exe", "pwsh.exe"}},
	)
	require.NoError(t, err)

	ev, err := NewEvaluator(uuid.New().String(), "spawn_process and ps.name in shells", WithMacros(store))
	require.NoError(t, err)

	// fields from the expanded macro body are collected
	assert.ElementsMatch(t, []string{"evt.name", "ps.name"}, fieldNames(ev))
	assert.False(t, ev.IsSequenceExpr())

	valuer := AcquireValuerCache()
	assert.True(t, ev.Eval(testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "cmd.exe"))), valuer))
	valuer.Release()

	valuer = AcquireValuerCache()
	assert.False(t, ev.Eval(testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "notepad.exe"))), valuer))
	valuer.Release()

	// macros are not available without the store
	_, err = NewEvaluator(uuid.New().String(), "spawn_process and ps.name in shells")
	require.Error(t, err)

	// the macro store in sequence steps
	ev, err = NewEvaluator(uuid.New().String(), `sequence
		maxspan 1s
		|spawn_process|
		|evt.name = 'CreateFile'|
	`, WithMacros(store))
	require.NoError(t, err)
	assert.True(t, ev.IsSequenceExpr())
}

func TestEvaluatorBooleanFields(t *testing.T) {
	ev, err := NewEvaluator(uuid.New().String(), "evt.name = 'CreateFile' and not file.is_exec")
	require.NoError(t, err)
	assert.Contains(t, fieldNames(ev), "file.is_exec")
}

func TestEvaluatorBoundFields(t *testing.T) {
	ev, err := NewEvaluator(uuid.New().String(), `sequence
		|evt.name = 'CreateProcess'| as e1
		|evt.name = 'CreateFile' and ps.sid != $e1.ps.sid|
	`)
	require.NoError(t, err)

	var bound []Field
	for _, f := range ev.GetFields() {
		if f.IsBound() {
			bound = append(bound, f)
		}
	}
	require.Len(t, bound, 1)
	assert.Equal(t, "$e1.ps.sid", bound[0].Value)
	assert.Equal(t, fields.PsSID, bound[0].Name)
}

// func TestScope(t *testing.T) {
// 	types := func(ts ...event.Type) Scope {
// 		s := make(Scope)
// 		for _, typ := range ts {
// 			s[typ] = struct{}{}
// 		}
// 		return s
// 	}

// 	var tests = []struct {
// 		name    string
// 		expr    string
// 		scoped  bool
// 		scope   Scope
// 		isEmpty bool
// 	}{
// 		{"event name", "evt.name = 'CreateFile'", true, types(event.CreateFile), false},
// 		{"reversed operands", "'CreateFile' = evt.name", true, types(event.CreateFile), false},
// 		{"event names list", "evt.name in ('CreateFile', 'WriteFile') and file.path contains 'x'", true, types(event.CreateFile, event.WriteFile), false},
// 		{"case insensitive name", "evt.name iin ('createfile')", true, types(event.CreateFile), false},
// 		{"name with multiple types", "evt.name = 'Connect'", true, types(event.Connect, event.Connect), false},
// 		{"or of names", "evt.name = 'CreateFile' or evt.name = 'WriteFile'", true, types(event.CreateFile, event.WriteFile), false},
// 		{"parenthesized", "(evt.name = 'CreateFile') and ps.name = 'cmd.exe'", true, types(event.CreateFile), false},
// 		{"negated condition keeps scope", "evt.name = 'CreateFile' and not file.name = 'a'", true, types(event.CreateFile), false},
// 		{"category does not narrow the scope", "evt.name = 'CreateFile' and evt.category = 'registry'", true, types(event.CreateFile), false},
// 		{"contradicting names", "evt.name = 'CreateFile' and evt.name = 'WriteFile'", true, types(), true},
// 		{"unknown name", "evt.name = 'Bogus'", true, types(), true},
// 		{"category only is unscoped", "evt.category = 'net'", false, nil, false},
// 		{"no event constraint", "ps.name = 'cmd.exe'", false, nil, false},
// 		{"not equal is unscoped", "evt.name != 'CreateFile'", false, nil, false},
// 		{"or with unscoped branch", "evt.name = 'CreateFile' or ps.name = 'x'", false, nil, false},
// 		{"or of name and category", "evt.name = 'CreateFile' or evt.category = 'net'", false, nil, false},
// 		{"contains is unscoped", "evt.name contains 'File'", false, nil, false},
// 		{
// 			"sequence is the union of steps",
// 			"sequence |evt.name = 'CreateProcess'| |evt.name = 'CreateFile'|",
// 			true, types(event.CreateProcess, event.CreateFile), false,
// 		},
// 		{
// 			"sequence with an unscoped step",
// 			"sequence |evt.name = 'CreateProcess'| |ps.name = 'cmd.exe'|",
// 			false, nil, false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			ev, err := NewEvaluator(uuid.New().String(), tt.expr)
// 			require.NoError(t, err)

// 			scope := ev.scope
// 			assert.Equal(t, tt.scope, scope)
// 			assert.Equal(t, tt.isEmpty, scope.IsUnbounded())
// 		})
// 	}
// }

// func TestScopeHasAndTypes(t *testing.T) {
// 	ev, err := NewEvaluator(uuid.New().String(), "evt.name in ('CreateFile', 'WriteFile')")
// 	require.NoError(t, err)
// 	scope := ev.scope
// 	require.True(t, ok)

// 	// assert.True(t, scope.Has(event.CreateFile))
// 	// assert.True(t, scope.Has(event.WriteFile))
// 	// assert.False(t, scope.Has(event.DeleteFile))
// 	// assert.False(t, scope.Has(event.CreateProcess))
// 	//assert.Equal(t, []event.Type{event.CreateFile, event.WriteFile}, scope.Types())
// }
