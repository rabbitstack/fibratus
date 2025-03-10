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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
	"net"
	"strconv"
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

func TestSimpleSequence(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Command shell created a temp file"}
	f := filter.New(`
	sequence
	maxspan 100ms
  	|kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'| by ps.exe
  	|kevt.name = 'CreateFile' and file.path icontains 'temp'| by file.path
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	var tests = []struct {
		evts    []*kevent.Kevent
		matches []bool
	}{
		{[]*kevent.Kevent{{
			Type:      ktypes.CreateProcess,
			Name:      "CreateProcess",
			Timestamp: time.Now(),
			Tid:       2484,
			PID:       859,
			PS: &pstypes.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}, {
			Type:      ktypes.CreateFile,
			Name:      "CreateFile",
			Timestamp: time.Now(),
			Tid:       2484,
			PID:       859,
			Category:  ktypes.File,
			PS: &pstypes.PS{
				Name: "cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"}}}, []bool{false, true}},
		{[]*kevent.Kevent{{
			Type:      ktypes.CreateProcess,
			Name:      "CreateProcess",
			Timestamp: time.Now(),
			Tid:       2484,
			PID:       859,
			PS: &pstypes.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}, {
			Type:      ktypes.CreateFile,
			Name:      "CreateFile",
			Timestamp: time.Now(),
			Tid:       2484,
			PID:       859,
			Category:  ktypes.File,
			PS: &pstypes.PS{
				Name: "cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"}}}, []bool{false, false}},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			for idx, e := range tt.evts {
				assert.Equal(t, tt.matches[idx], ss.runSequence(e))
			}
		})
	}
}

func TestSimpleSequenceMultiplePartials(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Command shell created a temp file"}
	f := filter.New(`
	sequence
  maxspan 200ms
  by ps.pid
    |kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'|
    |kevt.name = 'CreateFile' and file.path icontains 'temp'|
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	// create random matches which don't satisfy the sequence link
	for i, pid := range []uint32{2343, 1024, 11122, 3450, 12319} {
		e1 := &kevent.Kevent{
			Type:      ktypes.CreateProcess,
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
			Name:      "CreateProcess",
			Tid:       2484,
			PID:       pid,
			PS: &pstypes.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: pid % 2},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}
		e2 := &kevent.Kevent{
			Type:      ktypes.CreateFile,
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond * 2),
			Name:      "CreateFile",
			Tid:       2484,
			PID:       pid * 2,
			Category:  ktypes.File,
			PS: &pstypes.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}
		require.False(t, ss.runSequence(e1))
		require.False(t, ss.runSequence(e2))
	}

	// expression matched multiple partials
	assert.Len(t, ss.partials[0], 5)
	assert.Len(t, ss.partials[1], 0)

	e1 := &kevent.Kevent{
		Seq:       20,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now().Add(time.Second),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\System32\\cmd.exe",
			Parent: &pstypes.PS{
				Name: "WmiPrvSE.exe",
			},
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	e2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Seq:       22,
		Timestamp: time.Now().Add(time.Second * time.Duration(2)),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\file.tmp"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.False(t, ss.runSequence(e1))
	// expression matched the partial that satisfy the sequence link
	assert.Len(t, ss.partials[0], 6)
	assert.Len(t, ss.partials[1], 0)
	require.True(t, ss.runSequence(e2))
	assert.Len(t, ss.partials[1], 1)

	require.Len(t, ss.matches, 2)
	assert.Equal(t, uint32(859), ss.matches[0].PID)
	assert.Equal(t, "WmiPrvSE.exe", ss.matches[0].PS.Parent.Name)
	assert.Equal(t, uint32(859), ss.matches[1].PID)
	assert.Equal(t, "C:\\Temp\\file.tmp", ss.matches[1].GetParamAsString(kparams.FilePath))
}

func TestSimpleSequenceDeadline(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Command shell created a temp file"}
	f := filter.New(`
	sequence
	maxspan 100ms
  	|kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'| by ps.exe
  	|kevt.name = 'CreateFile' and file.path icontains 'temp'| by file.path
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, ss.runSequence(e1))

	e2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	time.Sleep(time.Millisecond * 110)
	require.False(t, ss.runSequence(e2))

	require.Equal(t, sequenceInitialState, ss.currentState())
	assert.Len(t, ss.partials, 0)

	// now the state machine has transitioned
	// to the initial state, which means we should
	// be able to match the sequence if we reinsert
	// the events
	require.False(t, ss.runSequence(e1))
	require.True(t, ss.runSequence(e2))

	ss.clearLocked()
	require.Equal(t, sequenceInitialState, ss.currentState())
	assert.Len(t, ss.partials, 0)

	// assert the events again with the delay less than max span
	require.False(t, ss.runSequence(e1))
	time.Sleep(time.Millisecond * 85)
	require.True(t, ss.runSequence(e2))
}

func TestComplexSequence(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Phishing dropper outbound communication"}
	f := filter.New(`
	sequence
  maxspan 1h
  	|kevt.name = 'CreateProcess' and ps.child.name in ('firefox.exe', 'chrome.exe', 'edge.exe')| by ps.child.pid
		|kevt.name = 'CreateFile' and file.operation = 'CREATE' and file.extension = '.exe'| by ps.pid
  	|kevt.name in ('Send', 'Connect')| by ps.pid
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e1 := &kevent.Kevent{
		Seq:       1,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "explorer.exe",
			Exe:  "C:\\Windows\\system32\\explorer.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "firefox.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, ss.runSequence(e1))

	e2 := &kevent.Kevent{
		Seq:       2,
		Type:      ktypes.CreateFile,
		Timestamp: time.Now().Add(time.Millisecond * 250),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       2243,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, ss.runSequence(e2))

	assert.Len(t, ss.partials[0], 1)
	assert.Len(t, ss.partials[1], 1)

	e3 := &kevent.Kevent{
		Seq:       4,
		Type:      ktypes.ConnectTCPv4,
		Timestamp: time.Now().Add(time.Second),
		Category:  ktypes.Net,
		Name:      "Connect",
		Tid:       244,
		PID:       2243,
		PS: &pstypes.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.NetDIP: {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("10.0.2.3")},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	time.Sleep(time.Millisecond * 30)
	require.True(t, ss.runSequence(e3))

	time.Sleep(time.Millisecond * 50)

	ss.clearLocked()

	// FSM should transition from terminal to initial state
	require.Equal(t, sequenceInitialState, ss.currentState())

	require.False(t, ss.runSequence(e1))
	require.False(t, ss.runSequence(e2))
	time.Sleep(time.Millisecond * 15)
	require.True(t, ss.runSequence(e3))
}

func TestSequenceOOO(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "LSASS memory dumping via legitimate or offensive tools"}
	f := filter.New(`
	sequence
  maxspan 2m
  	|kevt.name = 'OpenProcess' and kevt.arg[exe] imatches '?:\\Windows\\System32\\lsass.exe'| by ps.uuid
		|kevt.name = 'CreateFile' and file.operation = 'CREATE' and file.extension = '.dmp'| by ps.uuid
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e1 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\rundll32.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\temp\\lsass.dmp"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.UnicodeString, Value: "CREATE"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, ss.runSequence(e1))
	require.Len(t, ss.partials[1], 1)
	assert.True(t, ss.partials[1][0].ContainsMeta(kevent.RuleSequenceOOOKey))

	e2 := &kevent.Kevent{
		Type:      ktypes.OpenProcess,
		Timestamp: time.Now(),
		Name:      "OpenProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\rundll32.exe",
		},
		Kparams: kevent.Kparams{
			kparams.Exe:           {Name: kparams.Exe, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\lsass.exe"},
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Flags, Value: uint32(0x1400), Flags: kevent.PsAccessRightFlags},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.True(t, ss.runSequence(e2))
	assert.Len(t, ss.partials[0], 1)
	assert.False(t, ss.partials[1][0].ContainsMeta(kevent.RuleSequenceOOOKey))
}

func TestSequenceGC(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	maxSequencePartialLifetime = time.Millisecond * 500

	c := &config.FilterConfig{Name: "LSASS memory dumping via legitimate or offensive tools"}
	f := filter.New(`
	sequence
  by ps.uuid
  	|kevt.name = 'OpenProcess' and kevt.arg[exe] imatches '?:\\Windows\\System32\\lsass.exe'|
		|kevt.name = 'CreateFile' and file.operation = 'CREATE' and file.extension = '.dmp'|
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e := &kevent.Kevent{
		Type:      ktypes.OpenProcess,
		Timestamp: time.Now(),
		Name:      "OpenProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\rundll32.exe",
		},
		Kparams: kevent.Kparams{
			kparams.Exe:           {Name: kparams.Exe, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\lsass.exe"},
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Flags, Value: uint32(0x1400), Flags: kevent.PsAccessRightFlags},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.False(t, ss.runSequence(e))
	assert.Len(t, ss.partials[0], 1)

	time.Sleep(time.Second)

	ss.gc()

	assert.Len(t, ss.partials[0], 0)
}

func TestSequenceExpire(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	var tests = []struct {
		c     *config.FilterConfig
		expr  string
		evts  []*kevent.Kevent
		wants bool
	}{
		{
			&config.FilterConfig{Name: "LSASS memory dumping via legitimate or offensive tools"},
			`sequence
  		 maxspan 2m
  			|kevt.name = 'OpenProcess' and kevt.arg[exe] imatches '?:\\Windows\\System32\\lsass.exe'| by ps.uuid
				|kevt.name = 'CreateFile' and file.operation = 'CREATE' and file.extension = '.dmp'| by ps.uuid
			`,
			[]*kevent.Kevent{
				{
					Type:      ktypes.OpenProcess,
					Timestamp: time.Now(),
					Name:      "OpenProcess",
					Tid:       2484,
					PID:       4143,
					PS: &pstypes.PS{
						Name: "cmd.exe",
						Exe:  "C:\\Windows\\system32\\rundll32.exe",
					},
					Kparams: kevent.Kparams{
						kparams.Exe:           {Name: kparams.Exe, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\lsass.exe"},
						kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
						kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Flags, Value: uint32(0x1400), Flags: kevent.PsAccessRightFlags},
					},
					Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
				},
				{
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
				},
			},
			true,
		},
		{
			&config.FilterConfig{Name: "System Binary Proxy Execution via Rundll32"},
			`sequence
  		 maxspan 2m
  			|kevt.name = 'CreateProcess' and ps.child.name = 'rundll32.exe'| by ps.child.pid
				|kevt.name = 'CreateProcess' and ps.child.name = 'connhost.exe'| by ps.pid
			`,
			[]*kevent.Kevent{
				{
					Seq:       1,
					Type:      ktypes.CreateProcess,
					Timestamp: time.Now(),
					Category:  ktypes.Process,
					Name:      "CreateProcess",
					Tid:       2484,
					PID:       859,
					PS: &pstypes.PS{
						Name: "explorer.exe",
						Exe:  "C:\\Windows\\system32\\explorer.exe",
					},
					Kparams: kevent.Kparams{
						kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
						kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "rundll32.exe"},
					},
					Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
				},
				{
					Seq:       2,
					Type:      ktypes.CreateProcess,
					Timestamp: time.Now(),
					Category:  ktypes.Process,
					Name:      "CreateProcess",
					Tid:       2484,
					PID:       2243,
					PS: &pstypes.PS{
						Name: "explorer.exe",
						Exe:  "C:\\Windows\\system32\\explorer.exe",
					},
					Kparams: kevent.Kparams{
						kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(12243)},
						kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "connhost.exe"},
					},
					Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
				},
				{
					Type: ktypes.TerminateProcess,
					Name: "TerminateProcess",
					Tid:  2484,
					PID:  859,
					PS: &pstypes.PS{
						Name: "cmd.exe",
						Exe:  "C:\\Windows\\system32\\svchost.exe",
					},
					Kparams: kevent.Kparams{
						kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(12243)},
						kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
					},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			f := filter.New(tt.expr, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
			require.NoError(t, f.Compile())

			ss := newSequenceState(f, tt.c)
			for _, evt := range tt.evts {
				if evt.IsTerminateProcess() {
					ss.expire(evt)
				} else {
					ss.runSequence(evt)
				}
			}

			require.Equal(t, tt.wants, ss.inExpired.Load())
			require.Len(t, ss.partials, 0)
			ss.runSequence(tt.evts[0])
			require.False(t, ss.inExpired.Load())
		})
	}
}

func TestSequenceBoundFields(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	maxSequencePartialLifetime = time.Millisecond * 500

	c := &config.FilterConfig{Name: "Command shell created a temp file with network outbound"}
	f := filter.New(`
	sequence
  maxspan 200ms
  	|kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'| as e1
  	|kevt.name = 'CreateFile' and file.path icontains 'temp' and $e1.ps.sid = ps.sid| as e2
  	|kevt.name = 'Connect' and ps.sid != $e2.ps.sid and ps.sid = $e1.ps.sid|
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
			SID:  "zinet",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now().Add(time.Millisecond * 20),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
			SID:  "nusret",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e3 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now().Add(time.Second),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
			SID:  "nusret",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e4 := &kevent.Kevent{
		Type:      ktypes.ConnectTCPv4,
		Timestamp: time.Now().Add(time.Second * 3),
		Name:      "Connect",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
			SID:  "zinet",
		},
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(80)},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("172.1.2.3")},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.False(t, ss.runSequence(e1))
	require.False(t, ss.runSequence(e2))
	require.False(t, ss.runSequence(e3))
	require.True(t, ss.runSequence(e4))
}

func TestSequenceBoundFieldsWithFunctions(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	maxSequencePartialLifetime = time.Millisecond * 500

	c := &config.FilterConfig{Name: "Command shell created a temp file with network outbound"}
	f := filter.New(`
 	sequence
  maxspan 5m
    |kevt.name = 'CreateFile' and file.path imatches '?:\\Windows\\System32\\*.dll'| as e1
    |kevt.name = 'RegSetValue' and registry.path ~= 'HKEY_CURRENT_USER\\Volatile Environment\\Notification Packages' 
			and 
		 get_reg_value(registry.path) iin (base($e1.file.path, false))|
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true, EnableRegistryKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

	e1 := &kevent.Kevent{
		Type:     ktypes.CreateFile,
		Name:     "CreateFile",
		Category: ktypes.File,
		Tid:      2484,
		PID:      859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\passwdflt.dll"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &kevent.Kevent{
		Type:     ktypes.RegSetValue,
		Name:     "RegSetValue",
		Category: ktypes.Registry,
		Tid:      2484,
		PID:      859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.RegPath: {Name: kparams.RegPath, Type: kparams.UnicodeString, Value: "HKEY_CURRENT_USER\\Volatile Environment\\Notification Packages"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()

	defer func() {
		_ = key.DeleteValue("Notification Packages")
	}()

	require.NoError(t, key.SetStringsValue("Notification Packages", []string{"secli", "passwdflt"}))

	require.False(t, ss.runSequence(e1))
	require.True(t, ss.runSequence(e2))
}

func TestIsExpressionEvaluable(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	c := &config.FilterConfig{Name: "Command shell created a temp file"}
	f := filter.New(`
	sequence
	maxspan 100ms
  	|kevt.name = 'CreateProcess' and ps.name = 'cmd.exe'| by ps.exe
  	|kevt.name = 'CreateFile' and file.path icontains 'temp'| by file.path
	`, &config.Config{Kstream: config.KstreamConfig{EnableFileIOKevents: true}, Filters: &config.Filters{}})
	require.NoError(t, f.Compile())

	ss := newSequenceState(f, c)

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
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &kevent.Kevent{
		Type: ktypes.RenameFile,
		Name: "RenameFile",
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	assert.False(t, ss.filter.GetSequence().Expressions[0].IsEvaluable(e2))
	assert.True(t, ss.filter.GetSequence().Expressions[0].IsEvaluable(e1))
}
