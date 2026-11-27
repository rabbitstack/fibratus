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

func TestBoundFieldsAreRecordedButNotExtracted(t *testing.T) {
	prog, err := NewProgram(uuid.New().String(), `sequence
	|evt.name = 'CreateProcess'| as e1
	|evt.name = 'CreateFile' and ps.name = $e1.ps.exe|`)
	require.NoError(t, err)

	// the bound field is recorded, so the extractor knows which data the expression needs
	bound := prog.GetBoundFields()
	require.Len(t, bound, 1)
	assert.Equal(t, "ps.exe", bound[0].String())

	// but it's never extracted from the evaluated event
	for _, f := range prog.GetFields() {
		assert.NotEqual(t, "ps.exe", f.String())
	}
	for _, f := range prog.extractor.fields {
		assert.NotEqual(t, "ps.exe", f.String())
	}
}

func TestBoundFieldDoesNotShadowUnboundField(t *testing.T) {
	ev, err := NewProgram(uuid.New().String(), `sequence
	|evt.name = 'CreateProcess' and ps.name = 'cmd.exe'| as e1
	|evt.name = 'CreateFile' and ps.name = $e1.ps.name|`)
	require.NoError(t, err)

	assert.Contains(t, fieldNames(ev), "ps.name")
	require.Len(t, ev.GetBoundFields(), 1)
	assert.Equal(t, "ps.name", ev.GetBoundFields()[0].String())
	assert.Len(t, ev.extractor.fields, len(ev.GetFields()))
}

func TestExtractorBindsFieldToItsEvaluator(t *testing.T) {
	prog, err := NewProgram(uuid.New().String(), `evt.pid = 1023 and evt.host = 'kitty'`)
	require.NoError(t, err)

	require.Len(t, prog.extractor.fields, 2)
	for _, f := range prog.extractor.fields {
		assert.NotNil(t, f.eval, f.String())
	}

	evt := &event.Event{PID: 1023, Host: "kitty"}
	assert.Equal(t, uint32(1023), prog.extractor.Extract(Field{Name: fields.EvtPID, Value: "evt.pid"}, evt))
	assert.Equal(t, "kitty", prog.extractor.Extract(Field{Name: fields.EvtHost, Value: "evt.host"}, evt))
}

func TestExtractFieldWithoutEvaluatorReturnsDefault(t *testing.T) {
	// a field that nobody serves is bound to no evaluator
	x := newExtractor([]Field{{Name: "no.such.field", Value: "no.such.field"}}, nil, nil)
	require.Len(t, x.fields, 1)
	assert.Nil(t, x.fields[0].eval)

	evt := &event.Event{PID: 1023}
	assert.Equal(t, "", x.Extract(Field{Name: "no.such.field", Value: "no.such.field"}, evt))
	assert.Nil(t, x.lookup(Field{Name: "no.such.field", Value: "no.such.field"}, evt))
}
