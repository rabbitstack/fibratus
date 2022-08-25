/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"syscall"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotterWrite(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	pid := uint32(os.Getpid())
	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: pid},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)

	ps := psnap.Find(pid)
	require.NotNil(t, ps)

	assert.Equal(t, pid, ps.PID)
	assert.Equal(t, uint32(8390), ps.Ppid)
	assert.Equal(t, "spotify.exe", ps.Name)
	assert.Equal(t, `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`, ps.Comm)
	assert.Equal(t, `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`, ps.Exe)
	assert.Equal(t, `admin\SYSTEM`, ps.SID)
	assert.Len(t, ps.Args, 14)
	assert.Equal(t, "--type=crashpad-handler", ps.Args[1])
	assert.Equal(t, "ps", filepath.Base(ps.Cwd))
	assert.True(t, len(ps.Envs) > 0)

	kevt = &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1232)},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: pid},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err = psnap.Write(kevt)
	require.NoError(t, err)

	ps = psnap.Find(1232)
	require.NotNil(t, ps)
	require.NotNil(t, ps.Parent)
	assert.Equal(t, `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`, ps.Parent.Exe)
}

func TestSnapshotterWriteKeventProcess(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.EnumProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1200)},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)
	require.NotNil(t, psnap.Find(1200))

	assert.Equal(t, uint32(1200), kevt.PS.PID)

	kevt = &kevent.Kevent{
		Type: ktypes.CreateProcess,
		PID:  1200,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1232)},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: 1200},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify-client.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err = psnap.Write(kevt)
	require.NoError(t, err)

	assert.Equal(t, uint32(1200), kevt.PS.PID)
	assert.Equal(t, "spotify.exe", kevt.PS.Name)
	require.NotNil(t, psnap.Find(1232))
}

func TestSnapshotterWriteNoPIDInParams(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	require.Error(t, psnap.Write(kevt))
}

func TestSnapshotterWriteThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(6599)},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}
	require.NoError(t, psnap.Write(kevt))

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateThread,
		Kparams: kevent.Kparams{
			kparams.ProcessID:        {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(6599)},
			kparams.ThreadID:         {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
			kparams.BasePrio:         {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
			kparams.ThreadEntrypoint: {Name: kparams.ThreadEntrypoint, Type: kparams.HexInt64, Value: kparams.Hex("0x7ffe2557ff80")},
			kparams.IOPrio:           {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.KstackBase:       {Name: kparams.KstackBase, Type: kparams.HexInt64, Value: kparams.Hex("0xffffc307810d6000")},
			kparams.KstackLimit:      {Name: kparams.KstackLimit, Type: kparams.HexInt64, Value: kparams.Hex("0xffffc307810cf000")},
			kparams.PagePrio:         {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
			kparams.UstackBase:       {Name: kparams.UstackBase, Type: kparams.HexInt64, Value: kparams.Hex("0x5260000")},
			kparams.UstackLimit:      {Name: kparams.UstackLimit, Type: kparams.HexInt64, Value: kparams.Hex("0x525f000")},
		},
	}

	require.NoError(t, psnap.Write(kevt1))

	ps := psnap.Find(uint32(6599))
	require.NotNil(t, ps)

	require.Len(t, ps.Threads, 1)

	thread := ps.Threads[3453]

	assert.Equal(t, uint32(3453), thread.Tid)
	assert.Equal(t, uint32(6599), thread.Pid)
	assert.Equal(t, uint8(13), thread.BasePrio)
	assert.Equal(t, kparams.Hex("0x7ffe2557ff80"), thread.Entrypoint)
	assert.Equal(t, uint8(2), thread.IOPrio)
	assert.Equal(t, uint8(5), thread.PagePrio)
	assert.Equal(t, kparams.Hex("0xffffc307810d6000"), thread.KstackBase)
	assert.Equal(t, kparams.Hex("0xffffc307810cf000"), thread.KstackLimit)
	assert.Equal(t, kparams.Hex("0x5260000"), thread.UstackBase)
	assert.Equal(t, kparams.Hex("0x525f000"), thread.UstackLimit)
}

func TestSnapshotterWriteThreadPIDInParams(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.CreateThread,
		Kparams: kevent.Kparams{
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ThreadID:        {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
		},
	}

	require.Error(t, psnap.Write(kevt))
}

func TestSnapshotterWritePSThreadMissingProc(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	pid := uint32(os.Getpid())
	kevt := &kevent.Kevent{
		Type:    ktypes.CreateThread,
		Kparams: kevent.Kparams{kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: pid}},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)

	ps := psnap.Find(pid)
	require.NotNil(t, ps)
	assert.Equal(t, pid, ps.PID)
	assert.Contains(t, ps.Name, "ps")
	assert.True(t, len(ps.Envs) > 0)
}

func TestSnapshotterWritePSThreadMissingProcIdle(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateThread,
		Kparams: kevent.Kparams{kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(0)}},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)
}

func TestSnapshotterWritePSThreadMissingProtectedProc(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateThread,
		Kparams: kevent.Kparams{kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(0)}},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)
}

func init() {
	reapPeriod = time.Millisecond * 45
}

func TestReapDeadProcesses(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	argv, err := syscall.UTF16PtrFromString(filepath.Join(os.Getenv("windir"), "notepad.exe"))
	require.NoError(t, err)

	err = syscall.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&si,
		&pi)

	require.NoError(t, err)

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: pi.ProcessId},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "calc.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `c:\\windows\\system32\\calc.exe`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `c:\\windows\\system32\\calc.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	require.NoError(t, psnap.Write(kevt))

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}
	require.NoError(t, psnap.Write(kevt1))

	require.True(t, psnap.Size() > 1)
	require.NoError(t, syscall.TerminateProcess(pi.Process, uint32(257)))
	time.Sleep(time.Millisecond * 100)

	require.True(t, psnap.Size() == 1)
}

func TestRemove(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	pid := uint32(os.Getpid())
	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: pid},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err := psnap.Write(kevt)
	require.NoError(t, err)

	require.True(t, psnap.Size() > 0)

	err = psnap.Remove(&kevent.Kevent{
		Type: ktypes.TerminateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: pid},
		},
	})
	require.NoError(t, err)
	require.True(t, psnap.Size() == 0)
}

func TestRemoveNoPidInParams(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}

	err := psnap.Write(kevt)
	require.Error(t, err)
	require.True(t, psnap.Size() == 0)
}

func TestRemoveThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(6599)},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
		},
	}
	require.NoError(t, psnap.Write(kevt))

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateThread,
		Kparams: kevent.Kparams{
			kparams.ProcessID:        {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(6599)},
			kparams.ThreadID:         {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
			kparams.BasePrio:         {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
			kparams.ThreadEntrypoint: {Name: kparams.ThreadEntrypoint, Type: kparams.HexInt64, Value: kparams.Hex("0x7ffe2557ff80")},
			kparams.IOPrio:           {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.KstackBase:       {Name: kparams.KstackBase, Type: kparams.HexInt64, Value: kparams.Hex("0xffffc307810d6000")},
			kparams.KstackLimit:      {Name: kparams.KstackLimit, Type: kparams.HexInt64, Value: kparams.Hex("0xffffc307810cf000")},
			kparams.PagePrio:         {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
			kparams.UstackBase:       {Name: kparams.UstackBase, Type: kparams.HexInt64, Value: kparams.Hex("0x5260000")},
			kparams.UstackLimit:      {Name: kparams.UstackLimit, Type: kparams.HexInt64, Value: kparams.Hex("0x525f000")},
		},
	}

	require.NoError(t, psnap.Write(kevt1))

	ps := psnap.Find(uint32(6599))
	require.NotNil(t, ps)
	require.Len(t, ps.Threads, 1)

	err := psnap.Remove(&kevent.Kevent{
		Type: ktypes.TerminateThread,
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(6599)},
			kparams.ThreadID:  {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
		},
	})
	require.NoError(t, err)
	require.Len(t, ps.Threads, 0)
}
