//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package event

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxParamBasics(t *testing.T) {
	p := NewParam(params.ProcessID, params.PID, uint64(42))
	require.NotNil(t, p)
	assert.Equal(t, "42", p.String())

	pars := Params{}
	pars.Append(params.ProcessName, params.String, "bash")
	assert.Equal(t, "bash", pars.MustGetString(params.ProcessName))
}

func TestLinuxEventTypeHelpers(t *testing.T) {
	e := &Event{Type: Execve, PID: 1}
	assert.False(t, e.IsCreateProcess())
	assert.Equal(t, RawSyscallTracepoint, e.Type.Source())
	assert.Equal(t, Process, e.Type.Category())
	assert.Equal(t, uint(Execve), e.Type.ID())

	processClone := &Event{Type: Clone, Params: Params{}}
	processClone.Params.Append(params.CloneFlags, params.Uint64, uint64(0))
	assert.True(t, processClone.IsCreateProcess())
	assert.False(t, processClone.IsCreateThread())

	threadClone := &Event{Type: Clone, Params: Params{}}
	threadClone.Params.Append(params.CloneFlags, params.Uint64, cloneThread)
	assert.False(t, threadClone.IsCreateProcess())
	assert.True(t, threadClone.IsCreateThread())
}
