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

	"github.com/google/uuid"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldsAreUnique(t *testing.T) {
	var f Fields
	f.Add(fields.PsName, "ps.name", "")
	f.Add(fields.PsName, "ps.name", "")
	f.Add(fields.FileName, "file.name", "")
	// the field bound to a different aliases is a distinct field
	f.Add(fields.PsName, "$e1.ps.name", "e1")
	f.Add(fields.PsName, "$e1.ps.name", "e1")
	f.Add(fields.PsName, "$e2.ps.name", "e2")
	// fields with arguments are distinct from fields without
	f.Add(fields.EvtArg, "evt.arg", "cmdline")
	f.Add(fields.EvtArg, "evt.arg", "exe")

	assert.Len(t, f, 6)
}

func TestInterpolateFieldsUsesCompiledRegexp(t *testing.T) {
	require.NotNil(t, fieldsReplRegexp)

	evts := []*event.Event{{PID: 1023, Host: "kitty"}, {PID: 2048}}

	assert.Equal(t, "no modifiers", InterpolateFields("no modifiers", evts))
	assert.Equal(t, "pid 1023 on kitty", InterpolateFields("pid %evt.pid on %evt.host", evts))
	// the leading ordinal selects the event of the sequence stage
	assert.Equal(t, "1023 then 2048", InterpolateFields("%1.evt.pid then %2.evt.pid", evts))
	// the ordinal beyond the number of events leaves the modifier as is
	assert.Equal(t, "%3.evt.pid", InterpolateFields("%3.evt.pid", evts))
}

func TestProgramInterpolateFields(t *testing.T) {
	ev, err := NewProgram(uuid.New().String(), `evt.pid = 1023`)
	require.NoError(t, err)

	evts := []*event.Event{{PID: 1023, Host: "kitty"}}

	// the rule's extractor produces the same text as the package level function
	s := "pid %evt.pid on %evt.host"
	assert.Equal(t, InterpolateFields(s, evts), ev.InterpolateFields(s, evts))
	assert.Equal(t, "pid 1023 on kitty", ev.InterpolateFields(s, evts))

	// the evaluator is optional
	var noEvaluator *Program
	assert.Equal(t, "pid 1023 on kitty", noEvaluator.InterpolateFields(s, evts))
}

func TestFieldIntArg(t *testing.T) {
	var tests = []struct {
		name  string
		field Field
		n     int
		err   bool
	}{
		{"numeric argument", NewField(fields.PsAncestor, "ps.ancestor", "1"), 1, false},
		{"zero", NewField(fields.PsAncestor, "ps.ancestor", "0"), 0, false},
		{"negative", NewField(fields.PsAncestor, "ps.ancestor", "-1"), -1, false},
		{"not a number", NewField(fields.PsAncestor, "ps.ancestor", "parent"), 0, true},
		{"no argument", NewField(fields.PsName, "ps.name", ""), 0, true},
		// a field that wasn't made by NewField still parses its argument
		{"literal field", Field{Name: fields.PsAncestor, Value: "ps.ancestor", Arg: "7"}, 7, false},
		{"literal field with a bad argument", Field{Name: fields.PsAncestor, Value: "ps.ancestor", Arg: "x"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := tt.field.IntArg()
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.n, n)
		})
	}
}

func TestNewFieldParsesNumericArgumentOnce(t *testing.T) {
	f := NewField(fields.PsAncestor, "ps.ancestor", "3")
	assert.True(t, f.hasN)
	assert.Equal(t, 3, f.n)
	assert.Equal(t, "ps.ancestor[3]", f.String())

	// a string argument is left alone
	f = NewField(fields.EvtArg, "evt.arg", "cmdline")
	assert.False(t, f.hasN)
	assert.Equal(t, "cmdline", f.Arg)

	// the fields collected from an expression carry the parsed argument
	prog, err := NewProgram("ancestors", `ps.ancestor[1] = 'svchost.exe'`)
	if err != nil {
		t.Skipf("ps.ancestor isn't available on this platform: %v", err)
	}
	require.Len(t, prog.GetFields(), 1)
	n, err := prog.GetFields()[0].IntArg()
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.True(t, prog.GetFields()[0].hasN)
}
