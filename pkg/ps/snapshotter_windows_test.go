//go:build !integration

/*
 * Copyright 2016 by Nedim Sabic Sabic
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

package ps

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var mapper = NewMapper(Users())

var t0 = time.Unix(1700000000, 0)

// pids that are very unlikely to be assigned to the real processes,
// so the snapshotter doesn't pick any OS state for them
const (
	testPid  uint32 = 0x7ffffff1
	testPid2 uint32 = 0x7ffffff2
	testPid3 uint32 = 0x7ffffff3
)

func newSnapshotter() Snapshotter {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	return NewSnapshotter(hsnap, &config.Config{})
}

func newPS(pid, ppid uint32, name string) *pstypes.PS {
	return &pstypes.PS{
		PID:     pid,
		Ppid:    ppid,
		Name:    name,
		Threads: make(map[uint32]pstypes.Thread),
		Modules: make([]pstypes.Module, 0),
		Mmaps:   make([]pstypes.Mmap, 0),
		Handles: make([]htypes.Handle, 0),
	}
}

func TestAddProcessLinksParent(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	parent := newPS(100, 4, "explorer.exe")
	parent.SeqNum, parent.ParentSeqNum = 1122, 2211
	parent.IsCreatedFromSystemLogger = true
	parent.InitUUID()
	child := newPS(200, 100, "cmd.exe")
	child.SeqNum, child.ParentSeqNum = 4422, 1122
	child.IsCreatedFromSystemLogger = true
	child.InitUUID()
	orphan := newPS(300, 9999, "calc.exe")

	require.NoError(t, psnap.AddProcess(parent))
	require.NoError(t, psnap.AddProcess(child))
	require.NoError(t, psnap.AddProcess(orphan))

	assert.Same(t, parent, child.Parent)
	assert.Nil(t, orphan.Parent)
	assert.Equal(t, uint32(3), psnap.Size())
}

func TestRemoveProcessResetsParent(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	parent := newPS(100, 4, "explorer.exe")
	parent.SeqNum, parent.ParentSeqNum = 1122, 2211
	parent.IsCreatedFromSystemLogger = true
	parent.InitUUID()
	child := newPS(200, 100, "cmd.exe")
	child.SeqNum, child.ParentSeqNum = 4422, 1122
	child.IsCreatedFromSystemLogger = true
	child.InitUUID()
	require.NoError(t, psnap.AddProcess(parent))
	require.NoError(t, psnap.AddProcess(child))
	require.NotNil(t, child.Parent)

	psnap.RemoveProcess(100)
	// process in dirty map, wait 6 seconds before lookup
	time.Sleep(time.Second * 6)

	_, ok := psnap.Find(100)
	assert.False(t, ok)
	// the child shouldn't keep the stale parent alive
	assert.Nil(t, child.Parent)
	assert.Equal(t, uint32(1), psnap.Size())
}

func TestAddProcessNil(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()
	require.NoError(t, psnap.AddProcess(nil))
	assert.Equal(t, uint32(0), psnap.Size())
}

func TestAddProcessFromCaptureIgnoresBogusState(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotterFromCapture(hsnap, &config.Config{})
	defer psnap.Close()

	// a process can't be its own parent. Otherwise, the
	// ancestors walk would never terminate
	require.NoError(t, psnap.AddProcess(newPS(0, 0, "Idle")))
	require.NoError(t, psnap.AddProcess(newPS(sys.InvalidProcessID, 4, "bogus")))
	assert.Equal(t, uint32(0), psnap.Size())
}

func TestProcessCountIsConsistent(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	before := processCount.Value()

	// updating the state of the same process doesn't produce the new item
	require.NoError(t, psnap.AddProcess(newPS(500, 4, "a.exe")))
	require.NoError(t, psnap.AddProcess(newPS(500, 4, "a.exe")))
	assert.Equal(t, before+1, processCount.Value())

	// removing the process that is not in the snapshot is a no-op
	psnap.RemoveProcess(500)
	psnap.RemoveProcess(500)
	psnap.RemoveProcess(501)
	assert.Equal(t, before, processCount.Value())
}

func TestAddRemoveThreadByPid(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	proc := newPS(600, 4, "a.exe")
	require.NoError(t, psnap.AddProcess(proc))

	before := threadCount.Value()

	psnap.AddThread(pstypes.Thread{Pid: 600, Tid: 7, StartAddress: va.Address(0x1234)})
	assert.Equal(t, before+1, threadCount.Value())
	require.Contains(t, proc.Threads, uint32(7))
	assert.Equal(t, va.Address(0x1234), proc.Threads[7].StartAddress)

	// the thread of the unknown process is ignored and doesn't skew the counter
	psnap.AddThread(pstypes.Thread{Pid: 601, Tid: 8})
	assert.Equal(t, before+1, threadCount.Value())

	psnap.RemoveThread(600, 7)
	assert.Empty(t, proc.Threads)
	assert.Equal(t, before, threadCount.Value())
}

func TestAddRemoveModule(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	proc := newPS(700, 4, "a.exe")
	require.NoError(t, psnap.AddProcess(proc))

	before := moduleCount.Value()
	mod := pstypes.Module{Name: `C:\Windows\System32\kernel32.dll`, BaseAddress: va.Address(0x7000), Size: 0x1000}

	psnap.AddModule(700, mod)
	// the module that is already in the state (e.g. rundown
	// following the load event) is not accounted twice
	psnap.AddModule(700, mod)
	assert.Len(t, proc.Modules, 1)
	assert.Equal(t, before+1, moduleCount.Value())

	// module of the unknown process
	psnap.AddModule(701, mod)
	assert.Equal(t, before+1, moduleCount.Value())

	found, ok := psnap.FindModule(va.Address(0x7000))
	require.True(t, ok)
	assert.Equal(t, mod.Name, found.Name)
	assert.Contains(t, psnap.FindAllModules(), mod.Name)

	// removing the module that doesn't exist must not decrement the counter
	psnap.RemoveModule(700, va.Address(0x9999))
	assert.Equal(t, before+1, moduleCount.Value())

	psnap.RemoveModule(700, va.Address(0x7000))
	psnap.RemoveModule(700, va.Address(0x7000))
	assert.Empty(t, proc.Modules)
	assert.Equal(t, before, moduleCount.Value())
}

func TestAddModuleOverridesExecutable(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	proc := newPS(710, 4, "Spotify.exe")
	proc.Exe = "Spotify.exe"
	require.NoError(t, psnap.AddProcess(proc))

	// modules unrelated to the process executable don't touch it
	psnap.AddModule(710, pstypes.Module{Name: `C:\Windows\System32\notepad.exe`, BaseAddress: 0x1000})
	assert.Equal(t, "Spotify.exe", proc.Exe)

	// the module of the process image carries the full path
	psnap.AddModule(710, pstypes.Module{Name: `C:\Spotify\Spotify.exe`, BaseAddress: 0x2000})
	assert.Equal(t, `C:\Spotify\Spotify.exe`, proc.Exe)
}

func TestAddRemoveMmap(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	proc := newPS(800, 4, "a.exe")
	require.NoError(t, psnap.AddProcess(proc))

	before := mmapCount.Value()
	mmap := pstypes.Mmap{File: `C:\Windows\System32\kernel32.dll`, BaseAddress: va.Address(0xffff23433), Size: 3098}

	psnap.AddMmap(800, mmap)
	psnap.AddMmap(801, mmap)
	require.Len(t, proc.Mmaps, 1)
	assert.Equal(t, before+1, mmapCount.Value())
	assert.Equal(t, mmap.File, proc.FindMmap(va.Address(0xffff23433)).File)

	psnap.RemoveMmap(800, va.Address(0x1))
	assert.Equal(t, before+1, mmapCount.Value())

	psnap.RemoveMmap(800, va.Address(0xffff23433))
	psnap.RemoveMmap(800, va.Address(0xffff23433))
	assert.Empty(t, proc.Mmaps)
	assert.Equal(t, before, mmapCount.Value())
}

func TestCloseIsIdempotent(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, psnap.Close())
		assert.NoError(t, psnap.Close())
	}()

	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("closing the snapshotter twice must not block")
	}
}

func TestDirtyStateSurvivesPidReuse(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	// use a pid that is unlikely to exist, so the lookups can't be served by the OS
	const pid uint32 = 0x7ffffff0

	old := dirtyPeriod
	dirtyPeriod = time.Millisecond * 300
	defer func() { dirtyPeriod = old }()

	first := newPS(pid, 4, "first.exe")
	psnap.Put(first)
	psnap.RemoveProcess(pid)

	proc, ok := psnap.Find(pid)
	require.True(t, ok)
	assert.Same(t, first, proc)

	time.Sleep(time.Millisecond * 150)

	// the pid is reused by the new process that terminates quickly
	second := newPS(pid, 4, "second.exe")
	psnap.Put(second)
	psnap.RemoveProcess(pid)

	// the timer scheduled for the first process fires now (at ~300ms), but the
	// dirty state of the second process (valid until ~450ms) should be retained
	time.Sleep(time.Millisecond * 200)
	proc, ok = psnap.Find(pid)
	require.True(t, ok)
	assert.Same(t, second, proc)

	// and is eventually discarded
	time.Sleep(time.Millisecond * 300)
	_, ok = psnap.Find(pid)
	assert.False(t, ok)
}

func TestAddProcessKeepsTokenForRepeatedSystemEvents(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	newEvt := func(typ event.Type) *event.Event {
		return &event.Event{
			Type: typ,
			Params: event.ParamsOf(
				event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
				event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
				event.NewParam(params.ProcessName, params.String, params.Str("fibratus.exe")),
				event.NewParam(params.Cmdline, params.String, params.Str(`fibratus.exe run`)),
				event.NewParam(params.Exe, params.String, params.Str(`fibratus.exe`)),
				event.NewParam(params.UserSID, params.WbemSID, params.Bin(systemSID)),
				event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
				event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0))),
			),
		}
	}

	_ = psnap.AddProcess(mapper.Proc(newEvt(event.CreateProcess)))
	proc, ok := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotEmpty(t, proc.TokenIntegrityLevel)
	level := proc.TokenIntegrityLevel

	// the rundown event for the process that is already in the snapshot
	// must not wipe the token attributes obtained from the OS
	_ = psnap.AddProcess(mapper.Proc(newEvt(event.ProcessRundown)))
	proc, ok = psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	assert.Equal(t, level, proc.TokenIntegrityLevel)
}

func TestAddProcess(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	var tests = []struct {
		name string
		evt  *event.Event
		want *pstypes.PS
	}{
		{"add state from spawned process",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
					event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
					event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
					event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
					event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
					event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
					event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
					event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
				),
			},
			&pstypes.PS{
				PID:         uint32(os.Getpid()),
				Ppid:        uint32(os.Getppid()),
				Name:        "spotify.exe",
				Cmdline:     `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`,
				Exe:         `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`,
				Cwd:         "C:\\fibratus\\pkg\\ps",
				SessionID:   1,
				SID:         "S-1-5-18",
				Username:    "SYSTEM",
				Domain:      "NT AUTHORITY",
				IsWOW64:     true,
				IsPackaged:  true,
				IsProtected: false,
			},
		},
		{"add state from spawned process with parent",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getppid()))),
					event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
					event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
					event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
					event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
					event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
					event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
					event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
				),
				PID: uint32(os.Getpid()),
			},
			&pstypes.PS{
				PID:     uint32(os.Getppid()),
				Ppid:    uint32(os.Getpid()),
				Name:    "spotify.exe",
				Cmdline: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`,
				Exe:     `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`,
				Cwd:     "C:\\fibratus\\fibratus",
				Parent: &pstypes.PS{
					PID: uint32(os.Getpid()),
				},
				SessionID:   1,
				SID:         "S-1-5-18",
				Username:    "SYSTEM",
				Domain:      "NT AUTHORITY",
				IsWOW64:     true,
				IsPackaged:  true,
				IsProtected: false,
			},
		},
		{"add state from rundown event",
			&event.Event{
				Type: event.ProcessRundown,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(8390))),
					event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
					event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
					event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
					event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
					event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
					event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
					event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
				),
			},
			&pstypes.PS{
				PID:         uint32(os.Getpid()),
				Ppid:        8390,
				Name:        "spotify.exe",
				Cmdline:     `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`,
				Exe:         `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`,
				Cwd:         "C:\\fibratus\\pkg\\ps",
				SessionID:   1,
				SID:         "S-1-5-18",
				Username:    "SYSTEM",
				Domain:      "NT AUTHORITY",
				IsWOW64:     true,
				IsPackaged:  true,
				IsProtected: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			ps := tt.want

			require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))
			require.True(t, psnap.Size() > 0)

			proc, ok := psnap.Find(evt.Params.GetPid())
			require.True(t, ok)
			require.NotNil(t, proc)
			assert.Equal(t, ps.PID, proc.PID)
			assert.Equal(t, ps.Ppid, proc.Ppid)
			assert.Equal(t, ps.Name, proc.Name)
			assert.Equal(t, ps.Cmdline, proc.Cmdline)
			assert.Equal(t, ps.Exe, proc.Exe)
			assert.Equal(t, ps.SessionID, proc.SessionID)
			assert.Equal(t, ps.SID, proc.SID)
			assert.Equal(t, ps.Username, proc.Username)
			assert.Equal(t, ps.Domain, proc.Domain)
			assert.Equal(t, filepath.Base(ps.Cwd), filepath.Base(proc.Cwd))
			assert.Len(t, proc.Args, 13)
			assert.True(t, len(proc.Envs) > 0)

			assert.True(t, (ps.Parent != nil) == (proc.Parent != nil))
		})
	}
}

func TestAddProcessInternalEventsEnrichment(t *testing.T) {
	var tests = []struct {
		name       string
		evts       []*event.Event
		psnap      Snapshotter
		assertions func(t *testing.T, psnap Snapshotter)
	}{
		{"add internal event without previous state",
			[]*event.Event{
				{
					Type: event.CreateProcessInternal,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1024))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
						event.NewParam(params.ProcessTokenIntegrityLevel, params.String, params.Str("HIGH")),
						event.NewParam(params.ProcessTokenIsElevated, params.Bool, params.Boolean(true)),
						event.NewParam(params.ProcessTokenElevationType, params.String, params.Str("FULL")),
					),
				},
			},
			newSnapshotter(),
			func(t *testing.T, psnap Snapshotter) {
				proc, ok := psnap.Find(1024)
				assert.True(t, ok)
				assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
				assert.Equal(t, "FULL", proc.TokenElevationType)
				assert.Equal(t, true, proc.IsTokenElevated)
				assert.Equal(t, `C:\Windows\System32\svchost.exe`, proc.Exe)
			},
		},
		{"enrich existing system provider proc state with internal event",
			[]*event.Event{
				{
					Type: event.CreateProcess,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.Exe, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.ProcessName, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.Cmdline, params.String, params.Str(`svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`)),
						event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
						event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
						event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
					),
				},
				{
					Type: event.CreateProcessInternal,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
						event.NewParam(params.ProcessTokenIntegrityLevel, params.String, params.Str("HIGH")),
						event.NewParam(params.ProcessTokenIsElevated, params.Bool, params.Boolean(true)),
						event.NewParam(params.ProcessTokenElevationType, params.String, params.Str("FULL")),
					),
				},
			},
			newSnapshotter(),
			func(t *testing.T, psnap Snapshotter) {
				proc, ok := psnap.Find(uint32(os.Getpid()))
				assert.True(t, ok)
				assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
				assert.Equal(t, "FULL", proc.TokenElevationType)
				assert.Equal(t, true, proc.IsTokenElevated)
				assert.Equal(t, `C:\Windows\System32\svchost.exe`, proc.Exe)
				assert.Equal(t, "svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService", proc.Cmdline)
				assert.Equal(t, uint32(1), proc.SessionID)
			},
		},
		{"enrich newly arrived system provider proc with previous internal event state",
			[]*event.Event{
				{
					Type: event.CreateProcessInternal,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
						event.NewParam(params.ProcessName, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.ProcessTokenIntegrityLevel, params.String, params.Str("HIGH")),
						event.NewParam(params.ProcessTokenIsElevated, params.Bool, params.Boolean(true)),
						event.NewParam(params.ProcessTokenElevationType, params.String, params.Str("FULL")),
					),
				},
				{
					Type: event.CreateProcess,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.ProcessName, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.Exe, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.Cmdline, params.String, params.Str(`svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`)),
						event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
						event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
						event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
					),
				},
			},
			newSnapshotter(),
			func(t *testing.T, psnap Snapshotter) {
				proc, ok := psnap.Find(uint32(os.Getpid()))
				assert.True(t, ok)
				assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
				assert.Equal(t, "FULL", proc.TokenElevationType)
				assert.Equal(t, true, proc.IsTokenElevated)
				assert.Equal(t, `C:\Windows\System32\svchost.exe`, proc.Exe)
				assert.Equal(t, "svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService", proc.Cmdline)
				assert.Equal(t, uint32(1), proc.SessionID)
			},
		},
		{"consult process token integrity level from OS",
			[]*event.Event{
				{
					Type: event.CreateProcess,
					Params: event.ParamsOf(
						event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
						event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
						event.NewParam(params.Exe, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.ProcessName, params.String, params.Str(`svchost.exe`)),
						event.NewParam(params.Cmdline, params.String, params.Str(`svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`)),
						event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
						event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
						event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
					),
				},
			},
			newSnapshotter(),
			func(t *testing.T, psnap Snapshotter) {
				proc, ok := psnap.Find(uint32(os.Getpid()))
				assert.True(t, ok)
				assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
				assert.Equal(t, true, proc.IsTokenElevated)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, evt := range tt.evts {
				require.NoError(t, tt.psnap.AddProcess(mapper.Proc(evt)))
			}
			if tt.assertions != nil {
				tt.assertions(t, tt.psnap)
			}
			defer tt.psnap.Close()
		})
	}
}

func TestRemoveProcess(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	var tests = []struct {
		name string
		evt  *event.Event
		want bool
	}{
		{"add and remove process state from snapshotter",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
					event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
					event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
					event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
					event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
					event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
					event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
					event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
				),
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))
			require.True(t, psnap.Size() > 0)
			psnap.RemoveProcess(evt.Params.GetPid())
			// process in dirty map, wait 6 seconds before lookup
			time.Sleep(time.Second * 6)
			_, ok := psnap.Find(evt.Params.GetPid())
			assert.Equal(t, exists, ok)
		})
	}
}

func TestAddThread(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
			event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
			event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
		),
	}
	require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))

	var tests = []struct {
		name string
		evt  *event.Event
		want bool
	}{
		{"add thread to existing process",
			&event.Event{
				Type: event.CreateThread,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ThreadID, params.TID, params.U32(uint32(3453))),
					event.NewParam(params.BasePrio, params.Uint8, params.U8(uint8(13))),
					event.NewParam(params.StartAddress, params.Address, params.U64(uint64(140729524944768))),
					event.NewParam(params.IOPrio, params.Uint8, params.U8(uint8(2))),
					event.NewParam(params.KstackBase, params.Address, params.U64(uint64(18446677035730165760))),
					event.NewParam(params.KstackLimit, params.Address, params.U64(uint64(18446677035730137088))),
					event.NewParam(params.PagePrio, params.Uint8, params.U8(uint8(5))),
					event.NewParam(params.UstackBase, params.Address, params.U64(uint64(86376448))),
					event.NewParam(params.UstackLimit, params.Address, params.U64(uint64(86372352))),
				),
			},
			true,
		},
		{"add thread to absent process",
			&event.Event{
				Type: event.CreateThread,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()+1))),
					event.NewParam(params.ThreadID, params.TID, params.U32(uint32(3453))),
					event.NewParam(params.BasePrio, params.Uint8, params.U8(uint8(13))),
					event.NewParam(params.StartAddress, params.Address, params.U64(uint64(140729524944768))),
					event.NewParam(params.IOPrio, params.Uint8, params.U8(uint8(2))),
					event.NewParam(params.KstackBase, params.Address, params.U64(uint64(18446677035730165760))),
					event.NewParam(params.KstackLimit, params.Address, params.U64(uint64(18446677035730137088))),
					event.NewParam(params.PagePrio, params.Uint8, params.U8(uint8(5))),
					event.NewParam(params.UstackBase, params.Address, params.U64(uint64(86376448))),
					event.NewParam(params.UstackLimit, params.Address, params.U64(uint64(86372352))),
				),
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			psnap.AddThread(mapper.Thread(evt))
			proc, ok := psnap.Find(evt.Params.GetPid())
			require.Equal(t, exists, ok)
			if ok {
				assert.Contains(t, proc.Threads, evt.Params.GetTid())
				assert.Equal(t, va.Address(140729524944768), proc.Threads[evt.Params.GetTid()].StartAddress)
			}
		})
	}
}

func TestRemoveThread(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	pevt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
			event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
			event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
		),
	}
	require.NoError(t, psnap.AddProcess(mapper.Proc(pevt)))

	tevt := &event.Event{
		Type: event.CreateThread,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ThreadID, params.TID, params.U32(uint32(3453))),
			event.NewParam(params.BasePrio, params.Uint8, params.U8(uint8(13))),
			event.NewParam(params.StartAddress, params.Address, params.U64(uint64(140729524944768))),
			event.NewParam(params.IOPrio, params.Uint8, params.U8(uint8(2))),
			event.NewParam(params.KstackBase, params.Address, params.U64(uint64(18446677035730165760))),
			event.NewParam(params.KstackLimit, params.Address, params.U64(uint64(18446677035730137088))),
			event.NewParam(params.PagePrio, params.Uint8, params.U8(uint8(5))),
			event.NewParam(params.UstackBase, params.Address, params.U64(uint64(86376448))),
			event.NewParam(params.UstackLimit, params.Address, params.U64(uint64(86372352))),
		),
	}

	psnap.AddThread(mapper.Thread(tevt))

	ps, ok := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotNil(t, ps)
	require.Len(t, ps.Threads, 1)
	psnap.RemoveThread(uint32(os.Getpid()), 3453)
	require.Len(t, ps.Threads, 0)
}

func TestAddModule(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
			event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
			event.NewParam(params.Exe, params.String, params.Str(`Spotify.exe`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
		),
	}
	require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))

	var tests = []struct {
		name string
		evt  *event.Event
		want bool
	}{
		{"add module to existing process",
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe")),
				),
			},
			true,
		},
		{"add module to absent process",
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()+1))),
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Windows\\System32\\notepad.exe")),
				),
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			psnap.AddModule(mapper.Module(evt))
			proc, ok := psnap.Find(evt.Params.GetPid())
			require.Equal(t, exists, ok)
			if ok {
				require.NotNil(t, proc.FindModule(evt.GetParamAsString(params.ModulePath)))
				assert.Equal(t, "C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe", proc.Exe)
			}
		})
	}
}

func TestRemoveModule(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	pevt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
			event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
			event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
		),
	}
	require.NoError(t, psnap.AddProcess(mapper.Proc(pevt)))

	mevt := &event.Event{
		Type: event.LoadModule,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ModulePath, params.String, params.Str("C:\\Windows\\System32\\notepad.exe")),
			event.NewParam(params.ModuleBase, params.Address, params.U64(uint64(0xffff7656))),
		),
	}

	psnap.AddModule(mapper.Module(mevt))

	ps, ok := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotNil(t, ps)
	require.Len(t, ps.Modules, 1)
	psnap.RemoveModule(uint32(os.Getpid()), va.Address(0xffff7656))
	require.Len(t, ps.Modules, 0)
}

func TestOverrideProcExecutable(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(os.Getppid()))),
			event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
			event.NewParam(params.Exe, params.String, params.Str(`Spotify.exe`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
		),
	}
	require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))

	var tests = []struct {
		expectedExe string
		evt         *event.Event
	}{
		{`Spotify.exe`,
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Windows\\assembly\\NativeModules_v4.0.30319_32\\Microsoft.Dee252aac#\\707569faabe821b47fa4f59ecd9eb6ea\\Microsoft.Developer.IdentityService.ni.exe")),
				),
			},
		},
		{`Spotify.exe`,
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Windows\\System32\\notepad.exe")),
				),
			},
		},
		{`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`,
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe")),
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedExe, func(t *testing.T) {
			evt := tt.evt
			psnap.AddModule(mapper.Module(evt))
			ps, ok := psnap.Find(uint32(os.Getpid()))
			require.True(t, ok)
			assert.Equal(t, tt.expectedExe, ps.Exe)
		})
	}
}

func TestAddThreadCountsOnlyNewThreads(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	require.NoError(t, psnap.AddProcess(newPS(800, 4, "a.exe")))
	before := threadCount.Value()

	psnap.AddThread(pstypes.Thread{Pid: 800, Tid: 1})
	// the rundown event for the thread we already know about
	psnap.AddThread(pstypes.Thread{Pid: 800, Tid: 1})
	assert.Equal(t, before+1, threadCount.Value())

	// removing the thread that is not there doesn't skew the counter
	psnap.RemoveThread(800, 99)
	assert.Equal(t, before+1, threadCount.Value())
	psnap.RemoveThread(800, 1)
	psnap.RemoveThread(800, 1)
	assert.Equal(t, before, threadCount.Value())
}

func TestConcurrentModuleAndThreadUpdates(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	proc := newPS(810, 4, "Spotify.exe")
	proc.Exe = "Spotify.exe"
	require.NoError(t, psnap.AddProcess(proc))

	modsBefore, mmapsBefore, threadsBefore := moduleCount.Value(), mmapCount.Value(), threadCount.Value()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				addr := va.Address(0x10000 + i*0x1000)
				psnap.AddModule(810, pstypes.Module{Name: `C:\Spotify\Spotify.exe`, BaseAddress: addr})
				psnap.AddThread(pstypes.Thread{Pid: 810, Tid: uint32(i)})
				psnap.AddMmap(810, pstypes.Mmap{BaseAddress: addr})
				proc.FindModule(`Spotify.exe`)
				proc.FindModuleByVa(addr)
				psnap.RemoveMmap(810, addr)
				psnap.RemoveModule(810, addr)
				psnap.RemoveThread(810, uint32(i))
			}
		}(g)
	}
	wg.Wait()

	// every add was paired with a remove, so the counters are back where they started
	assert.Equal(t, modsBefore, moduleCount.Value())
	assert.Equal(t, mmapsBefore, mmapCount.Value())
	assert.Equal(t, threadsBefore, threadCount.Value())
	assert.Equal(t, `C:\Spotify\Spotify.exe`, proc.Exe)
}

// sysEvt builds the process creation event with the given identifiers and start time.
func sysEvt(pid, ppid uint32, start time.Time) *event.Event {
	e := processEvent(event.CreateProcess)
	e.Params.SetByName(params.ProcessID, params.U32(pid))
	e.Params.SetByName(params.ProcessParentID, params.U32(ppid))
	e.Params.SetByName(params.StartTime, params.Timestamp(start))
	e.Timestamp = start
	return e
}

// internalEvt builds the internal process creation event that carries the process
// and parent sequence numbers.
func internalEvt(pid, ppid uint32, seq, pseq uint64, start time.Time) *event.Event {
	return &event.Event{
		Type: event.CreateProcessInternal,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(pid)),
			event.NewParam(params.ProcessSequenceNumber, params.Uint64, params.U64(seq)),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(start)),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(ppid)),
			event.NewParam(params.ParentProcessSequenceNumber, params.Uint64, params.U64(pseq)),
			event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
			event.NewParam(params.ProcessTokenIntegrityLevel, params.String, params.Str("PROTECTED")),
			event.NewParam(params.ProcessTokenIsElevated, params.Bool, params.Boolean(true)),
			event.NewParam(params.ProcessTokenElevationType, params.String, params.Str("FULL")),
		),
	}
}

func TestSystemProcessInheritsSequenceNumberFromInternalEvent(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	stub := mapper.Proc(internalEvt(testPid, 4, 0xabc, 0xdef, t0))
	require.NoError(t, psnap.AddProcess(stub))

	proc := mapper.Proc(sysEvt(testPid, 4, t0.Add(5*time.Millisecond)))
	require.NoError(t, psnap.AddProcess(proc))

	// the UUID doesn't depend on the process being alive, and the system
	// state resolves to the one derived from the sequence number
	assert.Equal(t, uint64(0xabc), proc.SeqNum)
	assert.Equal(t, uint64(0xdef), proc.ParentSeqNum)
	assert.True(t, proc.IsUUIDExact())
	assert.Equal(t, stub.UUID(), proc.UUID())
	assert.Equal(t, "PROTECTED", proc.TokenIntegrityLevel)
}

func TestParentLinkedBySequenceNumber(t *testing.T) {
	psnap := newSnapshotter()
	defer psnap.Close()

	// the parent that owns the pid
	require.NoError(t, psnap.AddProcess(mapper.Proc(internalEvt(testPid, 4, 100, 0, t0))))
	parent := mapper.Proc(sysEvt(testPid, 4, t0))
	require.NoError(t, psnap.AddProcess(parent))

	// the child was spawned by the parent
	require.NoError(t, psnap.AddProcess(mapper.Proc(internalEvt(testPid2, testPid, 200, 100, t0.Add(time.Second)))))
	child := mapper.Proc(sysEvt(testPid2, testPid, t0.Add(time.Second)))
	require.NoError(t, psnap.AddProcess(child))
	require.Same(t, parent, child.Parent)

	// the grandchild was spawned by a process that is gone, and the
	// pid is held by the unrelated process now
	require.NoError(t, psnap.AddProcess(mapper.Proc(internalEvt(testPid3, testPid, 300, 99, t0.Add(2*time.Second)))))
	grandchild := mapper.Proc(sysEvt(testPid3, testPid, t0.Add(2*time.Second)))
	require.NoError(t, psnap.AddProcess(grandchild))
	assert.Nil(t, grandchild.Parent)
}
