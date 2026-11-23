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
