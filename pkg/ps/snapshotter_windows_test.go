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
		evt  *event.Event
		want *pstypes.PS
	}{
		{"write state from spawned process",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
					params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
					params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
					params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
					params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
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
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getppid())},
					params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
					params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
					params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
					params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
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
			&event.Event{
				Type: event.ProcessRundown,
				Params: event.Params{
					params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(8390)},
					params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
					params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
					params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
					params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
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

			ok, proc := psnap.Find(evt.Params.MustGetPid())
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

func TestWriteInternalEventsEnrichment(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)

	var tests = []struct {
		name       string
		evts       []*event.Event
		psnap      Snapshotter
		assertions func(t *testing.T, psnap Snapshotter)
	}{
		{"write internal event without previous state",
			[]*event.Event{
				{
					Type: event.CreateProcessInternal,
					Params: event.Params{
						params.ProcessID:                 {Name: params.ProcessID, Type: params.PID, Value: uint32(1024)},
						params.ProcessParentID:           {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:                       {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Windows\System32\svchost.exe`},
						params.ProcessIntegrityLevel:     {Name: params.ProcessIntegrityLevel, Type: params.AnsiString, Value: "HIGH"},
						params.ProcessTokenIsElevated:    {Name: params.ProcessTokenIsElevated, Type: params.Bool, Value: true},
						params.ProcessTokenElevationType: {Name: params.ProcessTokenElevationType, Type: params.AnsiString, Value: "FULL"},
					},
				},
			},
			NewSnapshotter(hsnap, &config.Config{}),
			func(t *testing.T, psnap Snapshotter) {
				ok, proc := psnap.Find(1024)
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
					Params: event.Params{
						params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(1024)},
						params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `svchost.exe`},
						params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`},
						params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
						params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
						params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
					},
				},
				{
					Type: event.CreateProcessInternal,
					Params: event.Params{
						params.ProcessID:                 {Name: params.ProcessID, Type: params.PID, Value: uint32(1024)},
						params.ProcessParentID:           {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:                       {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Windows\System32\svchost.exe`},
						params.ProcessIntegrityLevel:     {Name: params.ProcessIntegrityLevel, Type: params.AnsiString, Value: "HIGH"},
						params.ProcessTokenIsElevated:    {Name: params.ProcessTokenIsElevated, Type: params.Bool, Value: true},
						params.ProcessTokenElevationType: {Name: params.ProcessTokenElevationType, Type: params.AnsiString, Value: "FULL"},
					},
				},
			},
			NewSnapshotter(hsnap, &config.Config{}),
			func(t *testing.T, psnap Snapshotter) {
				ok, proc := psnap.Find(1024)
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
					Params: event.Params{
						params.ProcessID:                 {Name: params.ProcessID, Type: params.PID, Value: uint32(1024)},
						params.ProcessParentID:           {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:                       {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Windows\System32\svchost.exe`},
						params.ProcessIntegrityLevel:     {Name: params.ProcessIntegrityLevel, Type: params.AnsiString, Value: "HIGH"},
						params.ProcessTokenIsElevated:    {Name: params.ProcessTokenIsElevated, Type: params.Bool, Value: true},
						params.ProcessTokenElevationType: {Name: params.ProcessTokenElevationType, Type: params.AnsiString, Value: "FULL"},
					},
				},
				{
					Type: event.CreateProcess,
					Params: event.Params{
						params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(1024)},
						params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `svchost.exe`},
						params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`},
						params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
						params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
						params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
					},
				},
			},
			NewSnapshotter(hsnap, &config.Config{}),
			func(t *testing.T, psnap Snapshotter) {
				ok, proc := psnap.Find(1024)
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
					Params: event.Params{
						params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
						params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(444)},
						params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `svchost.exe`},
						params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`},
						params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
						params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
						params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
					},
				},
			},
			NewSnapshotter(hsnap, &config.Config{}),
			func(t *testing.T, psnap Snapshotter) {
				ok, proc := psnap.Find(uint32(os.Getpid()))
				assert.True(t, ok)
				assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
				assert.Equal(t, true, proc.IsTokenElevated)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, evt := range tt.evts {
				require.NoError(t, tt.psnap.Write(evt))
			}
			if tt.assertions != nil {
				tt.assertions(t, tt.psnap)
			}
			defer tt.psnap.Close()
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
		evt  *event.Event
		want bool
	}{
		{"write and remove process state from snapshotter",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
					params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
					params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
					params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
					params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
					params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
					params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
					params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
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
			ok, _ := psnap.Find(evt.Params.MustGetPid())
			assert.Equal(t, exists, ok)
		})
	}
}

func TestAddThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
			params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
			params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
			params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(evt))

	var tests = []struct {
		name string
		evt  *event.Event
		want bool
	}{
		{"add thread to existing process",
			&event.Event{
				Type: event.CreateThread,
				Params: event.Params{
					params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ThreadID:     {Name: params.ThreadID, Type: params.TID, Value: uint32(3453)},
					params.BasePrio:     {Name: params.BasePrio, Type: params.Uint8, Value: uint8(13)},
					params.StartAddress: {Name: params.StartAddress, Type: params.Address, Value: uint64(140729524944768)},
					params.IOPrio:       {Name: params.IOPrio, Type: params.Uint8, Value: uint8(2)},
					params.KstackBase:   {Name: params.KstackBase, Type: params.Address, Value: uint64(18446677035730165760)},
					params.KstackLimit:  {Name: params.KstackLimit, Type: params.Address, Value: uint64(18446677035730137088)},
					params.PagePrio:     {Name: params.PagePrio, Type: params.Uint8, Value: uint8(5)},
					params.UstackBase:   {Name: params.UstackBase, Type: params.Address, Value: uint64(86376448)},
					params.UstackLimit:  {Name: params.UstackLimit, Type: params.Address, Value: uint64(86372352)},
				},
			},
			true,
		},
		{"add thread to absent process",
			&event.Event{
				Type: event.CreateThread,
				Params: event.Params{
					params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid() + 1)},
					params.ThreadID:     {Name: params.ThreadID, Type: params.TID, Value: uint32(3453)},
					params.BasePrio:     {Name: params.BasePrio, Type: params.Uint8, Value: uint8(13)},
					params.StartAddress: {Name: params.StartAddress, Type: params.Address, Value: uint64(140729524944768)},
					params.IOPrio:       {Name: params.IOPrio, Type: params.Uint8, Value: uint8(2)},
					params.KstackBase:   {Name: params.KstackBase, Type: params.Address, Value: uint64(18446677035730165760)},
					params.KstackLimit:  {Name: params.KstackLimit, Type: params.Address, Value: uint64(18446677035730137088)},
					params.PagePrio:     {Name: params.PagePrio, Type: params.Uint8, Value: uint8(5)},
					params.UstackBase:   {Name: params.UstackBase, Type: params.Address, Value: uint64(86376448)},
					params.UstackLimit:  {Name: params.UstackLimit, Type: params.Address, Value: uint64(86372352)},
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
			ok, proc := psnap.Find(evt.Params.MustGetPid())
			require.Equal(t, exists, ok)
			if ok {
				assert.Contains(t, proc.Threads, evt.Params.MustGetTid())
				assert.Equal(t, va.Address(140729524944768), proc.Threads[evt.Params.MustGetTid()].StartAddress)
			}
		})
	}
}

func TestRemoveThread(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	defer psnap.Close()

	pevt := &event.Event{
		Type: event.CreateProcess,
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
			params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
			params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
			params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(pevt))

	tevt := &event.Event{
		Type: event.CreateThread,
		Params: event.Params{
			params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ThreadID:     {Name: params.ThreadID, Type: params.TID, Value: uint32(3453)},
			params.BasePrio:     {Name: params.BasePrio, Type: params.Uint8, Value: uint8(13)},
			params.StartAddress: {Name: params.StartAddress, Type: params.Address, Value: uint64(140729524944768)},
			params.IOPrio:       {Name: params.IOPrio, Type: params.Uint8, Value: uint8(2)},
			params.KstackBase:   {Name: params.KstackBase, Type: params.Address, Value: uint64(18446677035730165760)},
			params.KstackLimit:  {Name: params.KstackLimit, Type: params.Address, Value: uint64(18446677035730137088)},
			params.PagePrio:     {Name: params.PagePrio, Type: params.Uint8, Value: uint8(5)},
			params.UstackBase:   {Name: params.UstackBase, Type: params.Address, Value: uint64(86376448)},
			params.UstackLimit:  {Name: params.UstackLimit, Type: params.Address, Value: uint64(86372352)},
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

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
			params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
			params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `Spotify.exe`},
			params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
			params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(evt))

	var tests = []struct {
		name string
		evt  *event.Event
		want bool
	}{
		{"add module to existing process",
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe"},
				},
			},
			true,
		},
		{"add module to absent process",
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid() + 1)},
					params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\notepad.exe"},
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
			ok, proc := psnap.Find(evt.Params.MustGetPid())
			require.Equal(t, exists, ok)
			if ok {
				require.NotNil(t, proc.FindModule(evt.GetParamAsString(params.ImagePath)))
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

	pevt := &event.Event{
		Type: event.CreateProcess,
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
			params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
			params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --parent`},
			params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
			params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(pevt))

	mevt := &event.Event{
		Type: event.LoadImage,
		Params: event.Params{
			params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\notepad.exe"},
			params.ImageBase: {Name: params.ImageBase, Type: params.Address, Value: uint64(0xffff7656)},
		},
	}

	require.NoError(t, psnap.AddModule(mevt))

	ok, ps := psnap.Find(uint32(os.Getpid()))
	require.True(t, ok)
	require.NotNil(t, ps)
	require.Len(t, ps.Modules, 1)
	require.NoError(t, psnap.RemoveModule(uint32(os.Getpid()), va.Address(0xffff7656)))
	require.Len(t, ps.Modules, 0)
}

func TestOverrideProcExecutable(t *testing.T) {
	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	psnap := NewSnapshotter(hsnap, &config.Config{})
	defer psnap.Close()

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(os.Getppid())},
			params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
			params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
			params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `Spotify.exe`},
			params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
			params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
		},
	}
	require.NoError(t, psnap.Write(evt))

	var tests = []struct {
		expectedExe string
		evt         *event.Event
	}{
		{`Spotify.exe`,
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.Dee252aac#\\707569faabe821b47fa4f59ecd9eb6ea\\Microsoft.Developer.IdentityService.ni.exe"},
				},
			},
		},
		{`Spotify.exe`,
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\notepad.exe"},
				},
			},
		},
		{`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`,
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
					params.ImagePath: {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedExe, func(t *testing.T) {
			evt := tt.evt
			require.NoError(t, psnap.AddModule(evt))
			ok, ps := psnap.Find(uint32(os.Getpid()))
			require.True(t, ok)
			assert.Equal(t, tt.expectedExe, ps.Exe)
		})
	}
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

	evts := []*event.Event{
		{
			Type: event.CreateProcess,
			Params: event.Params{
				params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: notepadPID},
				params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(8390)},
				params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "notepad.exe"},
				params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `c:\\windows\\system32\\notepad.exe`},
				params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `c:\\windows\\system32\\notepad.exe`},
				params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
				params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
				params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
				params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
			},
		},
		{
			Type: event.CreateProcess,
			Params: event.Params{
				params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
				params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(8390)},
				params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
				params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
				params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
				params.UserSID:         {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
				params.StartTime:       {Name: params.StartTime, Type: params.Time, Value: time.Now()},
				params.SessionID:       {Name: params.SessionID, Type: params.Uint32, Value: uint32(1)},
				params.ProcessFlags:    {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x00000010)},
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
