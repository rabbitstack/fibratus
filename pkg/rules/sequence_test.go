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

package rules

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSequenceState(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Command shell created and executed by file"}
	f := filter.New(`
	sequence
  maxspan 100ms
  	|kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'| by ps.exe
  	|kevt.name = 'CreateFile' and file.path icontains 'temp'| by file.path
		|kevt.name = 'CreateProcess'| by ps.child.exe`,
		&config.Config{Kstream: config.KstreamConfig{}, Filters: &config.Filters{}})

	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	assert.Equal(t, 0, ss.currentState())
	assert.True(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.expr(ss.initialState))

	e1 := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(4143)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
		},
	}
	require.True(t, ss.next(0))
	require.False(t, ss.next(1))
	require.NoError(t, ss.matchTransition(0, e1))
	ss.addPartial(0, e1, false)
	require.True(t, ss.next(1))
	assert.True(t, ss.states[0])
	require.False(t, ss.next(2))

	assert.False(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateFile AND file.path ICONTAINS temp", ss.expr(ss.currentState()))

	e2 := &kevent.Kevent{
		Type: ktypes.CreateFile,
		Name: "CreateFile",
		Tid:  2484,
		PID:  4143,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
	}
	// can't go to the next transitions as the expr hasn't matched
	require.False(t, ss.next(2))
	require.NoError(t, ss.matchTransition(1, e2))
	ss.addPartial(1, e2, false)
	require.True(t, ss.states[1])
	require.True(t, ss.next(2))

	assert.Len(t, ss.partials[0], 1)
	assert.Len(t, ss.partials[1], 1)

	assert.Equal(t, 2, ss.currentState())
	assert.Equal(t, "kevt.name = CreateProcess", ss.expr(ss.currentState()))

	e3 := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  4143,
		Kparams: kevent.Kparams{
			kparams.Exe: {Name: kparams.Exe, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
		},
	}
	require.NoError(t, ss.matchTransition(2, e3))
	ss.addPartial(2, e3, false)

	assert.Len(t, ss.partials[2], 1)

	assert.Equal(t, sequenceTerminalState, ss.currentState())
	assert.True(t, ss.isTerminalState())

	// reset sequence state
	ss.clear()

	// reset transition leads back to initial state
	assert.Equal(t, 0, ss.currentState())
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.expr(ss.currentState()))
	// deadline exceeded
	require.NoError(t, ss.matchTransition(0, e1))
	assert.Equal(t, "kevt.name = CreateFile AND file.path ICONTAINS temp", ss.expr(ss.currentState()))
	time.Sleep(time.Millisecond * 120)
	// transition to initial state
	assert.True(t, ss.isInitialState())

	// sequence in deadline state
	require.True(t, ss.inDeadline.Load())
	require.True(t, ss.next(0))
	require.False(t, ss.next(1))
	if ss.next(1) {
		// this shouldn't happen
		require.NoError(t, ss.matchTransition(1, e2))
	}

	ss.clear()

	assert.True(t, ss.isInitialState())
	require.NoError(t, ss.matchTransition(0, e1))
	ss.addPartial(0, e1, false)
	ss.addPartial(1, e2, false)
	require.False(t, ss.inDeadline.Load())

	// expire entire sequence
	e4 := &kevent.Kevent{
		Type: ktypes.TerminateProcess,
		Name: "TerminateProcess",
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(4143)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
		},
	}
	require.True(t, ss.expire(e4))
	require.True(t, ss.inExpired.Load())

	require.NoError(t, ss.matchTransition(0, e1))
	require.False(t, ss.inExpired.Load())

	assert.Equal(t, "kevt.name = CreateFile AND file.path ICONTAINS temp", ss.expr(ss.currentState()))
}
