//go:build integration

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
	"strings"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var mapper = NewMapper(Users())

func init() {
	reapPeriod = time.Millisecond * 45
}

func TestReapDeadProcesses(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	notepadHandle, notepadPID := createProcess(filepath.Join(os.Getenv("windir"), "notepad.exe"), os.Getenv("windir"))
	if notepadHandle == 0 {
		t.Fatal("unable to spawn notepad process")
	}

	evts := []*event.Event{
		{
			Type: event.CreateProcess,
			Params: event.ParamsOf(
				event.NewParam(params.ProcessID, params.PID, params.U32(notepadPID)),
				event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(8390))),
				event.NewParam(params.ProcessName, params.String, params.Str("notepad.exe")),
				event.NewParam(params.Cmdline, params.String, params.Str(`c:\\windows\\system32\\notepad.exe`)),
				event.NewParam(params.Exe, params.String, params.Str(`c:\\windows\\system32\\notepad.exe`)),
				event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
				event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
				event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
				event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
			),
		},
		{
			Type: event.CreateProcess,
			Params: event.ParamsOf(
				event.NewParam(params.ProcessID, params.PID, params.U32(uint32(os.Getpid()))),
				event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(8390))),
				event.NewParam(params.ProcessName, params.String, params.Str("spotify.exe")),
				event.NewParam(params.Cmdline, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`)),
				event.NewParam(params.Exe, params.String, params.Str(`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`)),
				event.NewParam(params.UserSID, params.WbemSID, params.Bin([]byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})),
				event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
				event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(1))),
				event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(0x00000010))),
			),
		},
	}
	for _, evt := range evts {
		require.NoError(t, psnap.AddProcess(mapper.Proc(evt)))
	}

	require.True(t, psnap.Size() > 1)
	require.NoError(t, windows.TerminateProcess(notepadHandle, 257))
	time.Sleep(time.Millisecond * 100)

	require.True(t, psnap.Size() == 1)
}

func TestFindQueryOS(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	regeditHandle, regeditPID := createProcess(filepath.Join(os.Getenv("windir"), "regedit.exe"), os.Getenv("windir"))
	if regeditHandle == 0 {
		t.Fatal("unable to spawn regedit process")
	}
	defer func() {
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, regeditPID)
		if err != nil {
			t.Logf("unable to open process %d for termination: %v", regeditPID, err)
			return
		}
		defer windows.CloseHandle(h)
		if w, _ := windows.WaitForSingleObject(h, 0); w == windows.WAIT_OBJECT_0 {
			t.Logf("process %d already exited", regeditPID)
			return
		}

		if err := windows.TerminateProcess(h, 257); err != nil {
			t.Logf("TerminateProcess(%d): %v", regeditPID, err)
		}
	}()
	defer psnap.Close()

	waits := 0
	for !sys.IsProcessRunning(regeditHandle) {
		time.Sleep(time.Millisecond * 100)
		waits++
		if waits > 50 {
			break
		}
	}

	time.Sleep(time.Second * 2)

	proc, ok := psnap.Find(regeditPID)
	require.False(t, ok)
	require.NotNil(t, proc)

	assert.Equal(t, regeditPID, proc.PID)
	assert.Equal(t, "regedit.exe", strings.ToLower(proc.Name))
	assert.Equal(t, uint32(os.Getpid()), proc.Ppid)
	assert.True(t, proc.IsPackaged)
	assert.False(t, proc.IsWOW64)
	assert.False(t, proc.IsProtected)
	assert.Equal(t, strings.ToLower(filepath.Join(os.Getenv("windir"), "regedit.exe")), strings.ToLower(proc.Exe))
	assert.Equal(t, filepath.Join(os.Getenv("windir"), "regedit.exe"), proc.Cmdline)
	assert.True(t, len(proc.Envs) > 0)
	assert.Equal(t, os.Getenv("windir"), strings.TrimSuffix(proc.Cwd, `\`))
	assert.True(t, proc.SessionID > 0)
	assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)

	wts, err := sys.LookupActiveWTS()
	require.NoError(t, err)
	loggedSID, err := wts.SID()
	require.NoError(t, err)
	assert.Equal(t, loggedSID.String(), proc.SID)
	username, domain, _, err := loggedSID.LookupAccount("")
	require.NoError(t, err)
	assert.Equal(t, username, proc.Username)
	assert.Equal(t, domain, proc.Domain)

	// now the proc should exist in snapshotter state
	psnap.Put(proc)
	ps, found := psnap.Find(regeditPID)
	require.True(t, found)
	require.NotNil(t, ps)
}

func createProcess(path, cwd string) (windows.Handle, uint32) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	argv, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	workdir, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		return 0, 0
	}
	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		workdir,
		&si,
		&pi)
	if err != nil {
		return 0, 0
	}
	return pi.Process, pi.ProcessId
}
