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

package kevent

import (
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestKeventIsNetworkTCP(t *testing.T) {
	e1 := Kevent{Type: ktypes.AcceptTCPv4, Category: ktypes.Net}
	e2 := Kevent{Type: ktypes.SendUDPv6, Category: ktypes.Net}
	assert.True(t, e1.IsNetworkTCP())
	assert.False(t, e2.IsNetworkTCP())
}

func TestKeventIsNetworkUDP(t *testing.T) {
	e1 := Kevent{Type: ktypes.RecvUDPv4}
	e2 := Kevent{Type: ktypes.SendTCPv6}
	assert.True(t, e1.IsNetworkUDP())
	assert.False(t, e2.IsNetworkUDP())
}

func TestKeventSummary(t *testing.T) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
		PS: &pstypes.PS{
			PID:  2436,
			Ppid: 6304,
			Parent: &pstypes.PS{
				PID:  2034,
				Name: "explorer.exe",
				Exe:  `C:\Windows\System32\explorer.exe`,
				Cwd:  `C:\Windows\System32`,
				SID:  "admin\\SYSTEM",
				Parent: &pstypes.PS{
					PID:  2345,
					Name: "winlogon.exe",
				},
			},
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "archrabbit\\SYSTEM",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
		},
	}

	require.Equal(t, "<code>firefox.exe</code> opened a file <code>C:\\Windows\\system32\\user32.dll</code>", kevt.Summary())
	kevt.PS = nil
	require.Equal(t, "process with <code>859</code> id opened a file <code>C:\\Windows\\system32\\user32.dll</code>", kevt.Summary())
}

func TestPartialKey(t *testing.T) {
	var tests = []struct {
		evt *Kevent
		key uint64
	}{
		{
			&Kevent{Type: ktypes.OpenProcess, PID: 1234, Kparams: Kparams{kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1221)}, kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Uint32, Value: uint32(5)}}},
			0x99c,
		},
		{
			&Kevent{Type: ktypes.OpenThread, PID: 11234, Kparams: Kparams{kparams.ThreadID: {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(8452)}, kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Uint32, Value: uint32(15)}}},
			0x4cf5,
		},
		{
			&Kevent{Type: ktypes.CreateFile, PID: 4321, Kparams: Kparams{kparams.FileName: {Name: kparams.FileName, Type: kparams.FileDosPath, Value: "C:\\Windows\\System32\\kernelbase.dll"}}},
			0x7ec254f31df879ec,
		},
		{
			&Kevent{Type: ktypes.CreateFile, PID: 4321, Kparams: Kparams{kparams.FileName: {Name: kparams.FileName, Type: kparams.FileDosPath, Value: "C:\\Windows\\System32\\kernel32.dll"}}},
			0xb6380d9159ccd174,
		},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Equal(t, tt.key, tt.evt.PartialKey())
		})
	}
}
