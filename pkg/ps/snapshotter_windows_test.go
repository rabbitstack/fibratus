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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWrite(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	var tests = []struct {
		name string
		evt  *kevent.Kevent
		want *pstypes.PS
	}{
		{"write state from spawned process",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
					kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
					kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
					kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
					kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
				},
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
		{"write state from spawned process with parent",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getppid())},
					kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
					kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
					kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
					kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
				},
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
		{"write state from rundown event",
			&kevent.Kevent{
				Type: ktypes.ProcessRundown,
				Kparams: kevent.Kparams{
					kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
					kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
					kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
					kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
					kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
				},
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

			require.NoError(t, psnap.Write(evt))
			require.True(t, psnap.Size() > 0)

			ok, proc := psnap.Find(evt.Kparams.MustGetPid())
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
			if found, _ := psnap.Find(evt.PID); found {
				assert.NotNil(t, evt.PS)
				if evt.IsProcessRundown() {
					assert.Equal(t, ps.PID, evt.PS.PID)
				} else {
					assert.Equal(t, ps.Ppid, evt.PS.PID)
				}
			}
		})
	}
}

func TestRemove(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	var tests = []struct {
		name string
		evt  *kevent.Kevent
		want bool
	}{
		{"write and remove process state from snapshotter",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
					kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
					kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
					kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
					kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			require.NoError(t, psnap.Write(evt))
			require.True(t, psnap.Size() > 0)
			require.NoError(t, psnap.Remove(evt))
			// process in dirty map, wait 6 seconds before lookup
			time.Sleep(time.Second * 6)
			ok, _ := psnap.Find(evt.Kparams.MustGetPid())
			assert.Equal(t, exists, ok)
		})
	}
}

func TestAddThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	evt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
			kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(evt))

	var tests = []struct {
		name string
		evt  *kevent.Kevent
		want bool
	}{
		{"add thread to existing process",
			&kevent.Kevent{
				Type: ktypes.CreateThread,
				Kparams: kevent.Kparams{
					kparams.ProcessID:    {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ThreadID:     {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
					kparams.BasePrio:     {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
					kparams.StartAddress: {Name: kparams.StartAddress, Type: kparams.Address, Value: uint64(140729524944768)},
					kparams.IOPrio:       {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
					kparams.KstackBase:   {Name: kparams.KstackBase, Type: kparams.Address, Value: uint64(18446677035730165760)},
					kparams.KstackLimit:  {Name: kparams.KstackLimit, Type: kparams.Address, Value: uint64(18446677035730137088)},
					kparams.PagePrio:     {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
					kparams.UstackBase:   {Name: kparams.UstackBase, Type: kparams.Address, Value: uint64(86376448)},
					kparams.UstackLimit:  {Name: kparams.UstackLimit, Type: kparams.Address, Value: uint64(86372352)},
				},
			},
			true,
		},
		{"add thread to absent process",
			&kevent.Kevent{
				Type: ktypes.CreateThread,
				Kparams: kevent.Kparams{
					kparams.ProcessID:    {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid() + 1)},
					kparams.ThreadID:     {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
					kparams.BasePrio:     {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
					kparams.StartAddress: {Name: kparams.StartAddress, Type: kparams.Address, Value: uint64(140729524944768)},
					kparams.IOPrio:       {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
					kparams.KstackBase:   {Name: kparams.KstackBase, Type: kparams.Address, Value: uint64(18446677035730165760)},
					kparams.KstackLimit:  {Name: kparams.KstackLimit, Type: kparams.Address, Value: uint64(18446677035730137088)},
					kparams.PagePrio:     {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
					kparams.UstackBase:   {Name: kparams.UstackBase, Type: kparams.Address, Value: uint64(86376448)},
					kparams.UstackLimit:  {Name: kparams.UstackLimit, Type: kparams.Address, Value: uint64(86372352)},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			require.NoError(t, psnap.AddThread(evt))
			ok, proc := psnap.Find(evt.Kparams.MustGetPid())
			require.Equal(t, exists, ok)
			if ok {
				assert.Contains(t, proc.Threads, evt.Kparams.MustGetTid())
				assert.Equal(t, va.Address(140729524944768), proc.Threads[evt.Kparams.MustGetTid()].StartAddress)
			}
		})
	}
}

func TestRemoveThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	defer psnap.Close()

	pevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
			kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(pevt))

	tevt := &kevent.Kevent{
		Type: ktypes.CreateThread,
		Kparams: kevent.Kparams{
			kparams.ProcessID:    {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ThreadID:     {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
			kparams.BasePrio:     {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
			kparams.StartAddress: {Name: kparams.StartAddress, Type: kparams.Address, Value: uint64(140729524944768)},
			kparams.IOPrio:       {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.KstackBase:   {Name: kparams.KstackBase, Type: kparams.Address, Value: uint64(18446677035730165760)},
			kparams.KstackLimit:  {Name: kparams.KstackLimit, Type: kparams.Address, Value: uint64(18446677035730137088)},
			kparams.PagePrio:     {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
			kparams.UstackBase:   {Name: kparams.UstackBase, Type: kparams.Address, Value: uint64(86376448)},
			kparams.UstackLimit:  {Name: kparams.UstackLimit, Type: kparams.Address, Value: uint64(86372352)},
		},
	}

	require.NoError(t, psnap.AddThread(tevt))

	ok, ps := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotNil(t, ps)
	require.Len(t, ps.Threads, 1)
	require.NoError(t, psnap.RemoveThread(uint32(os.Getpid()), 3453))
	require.Len(t, ps.Threads, 0)
}

func TestAddModule(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	evt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `Spotify.exe`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
			kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(evt))

	var tests = []struct {
		name string
		evt  *kevent.Kevent
		want bool
	}{
		{"add module to existing process",
			&kevent.Kevent{
				Type: ktypes.LoadImage,
				Kparams: kevent.Kparams{
					kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
					kparams.ImageFilename: {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: "C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe"},
				},
			},
			true,
		},
		{"add module to absent process",
			&kevent.Kevent{
				Type: ktypes.LoadImage,
				Kparams: kevent.Kparams{
					kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid() + 1)},
					kparams.ImageFilename: {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\notepad.exe"},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := tt.evt
			exists := tt.want

			require.NoError(t, psnap.AddModule(evt))
			ok, proc := psnap.Find(evt.Kparams.MustGetPid())
			require.Equal(t, exists, ok)
			if ok {
				require.NotNil(t, proc.FindModule(evt.GetParamAsString(kparams.ImageFilename)))
				assert.Equal(t, "C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe", proc.Exe)
			}
		})
	}
}

func TestRemoveModule(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	pevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Kparams: kevent.Kparams{
			kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(os.Getppid())},
			kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
			kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
			kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(pevt))

	mevt := &kevent.Kevent{
		Type: ktypes.LoadImage,
		Kparams: kevent.Kparams{
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
			kparams.ImageFilename: {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\notepad.exe"},
		},
	}

	require.NoError(t, psnap.AddModule(mevt))

	ok, ps := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotNil(t, ps)
	require.Len(t, ps.Modules, 1)
	require.NoError(t, psnap.RemoveModule(uint32(os.Getpid()), "C:\\Windows\\System32\\notepad.exe"))
	require.Len(t, ps.Modules, 0)
}

func init() {
	reapPeriod = time.Millisecond * 45
}

func TestReapDeadProcesses(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	notepadHandle, notepadPID := spawnNotepad()
	if notepadHandle == 0 {
		t.Fatal("unable to spawn notepad process")
	}

	evts := []*kevent.Kevent{
		{
			Type: ktypes.CreateProcess,
			Kparams: kevent.Kparams{
				kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: notepadPID},
				kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
				kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "notepad.exe"},
				kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `c:\\windows\\system32\\notepad.exe`},
				kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `c:\\windows\\system32\\notepad.exe`},
				kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
				kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
				kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
				kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
			},
		},
		{
			Type: ktypes.CreateProcess,
			Kparams: kevent.Kparams{
				kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
				kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
				kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
				kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
				kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
				kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
				kparams.StartTime:       {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
				kparams.SessionID:       {Name: kparams.SessionID, Type: kparams.Uint32, Value: uint32(1)},
				kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x00000010)},
			},
		},
	}
	for _, evt := range evts {
		require.NoError(t, psnap.Write(evt))
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
	defer psnap.Close()

	notepadHandle, notepadPID := spawnNotepad()
	if notepadHandle == 0 {
		t.Fatal("unable to spawn notepad process")
	}
	time.Sleep(time.Second * 1)
	defer windows.TerminateProcess(notepadHandle, 257)
	ok, proc := psnap.Find(notepadPID)
	require.False(t, ok)
	require.NotNil(t, proc)

	assert.Equal(t, notepadPID, proc.PID)
	assert.Equal(t, "notepad.exe", strings.ToLower(proc.Name))
	assert.Equal(t, uint32(os.Getpid()), proc.Ppid)
	assert.True(t, proc.IsPackaged)
	assert.False(t, proc.IsWOW64)
	assert.False(t, proc.IsProtected)
	assert.Equal(t, strings.ToLower(filepath.Join(os.Getenv("windir"), "notepad.exe")), strings.ToLower(proc.Exe))
	assert.Equal(t, filepath.Join(os.Getenv("windir"), "notepad.exe"), proc.Cmdline)
	assert.True(t, len(proc.Envs) > 0)
	assert.Contains(t, proc.Cwd, "fibratus\\pkg\\ps")
	assert.Equal(t, uint32(1), proc.SessionID)

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
	found, ps := psnap.Find(notepadPID)
	require.True(t, found)
	require.NotNil(t, ps)
}

func spawnNotepad() (windows.Handle, uint32) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	argv, err := windows.UTF16PtrFromString(filepath.Join(os.Getenv("windir"), "notepad.exe"))
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
		nil,
		&si,
		&pi)
	if err != nil {
		return 0, 0
	}
	return pi.Process, pi.ProcessId
}
