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
	"github.com/rabbitstack/fibratus/pkg/callstack"
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
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
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
			&Kevent{Type: ktypes.CreateFile, PID: 4321, Kparams: Kparams{kparams.FilePath: {Name: kparams.FilePath, Type: kparams.DOSPath, Value: "C:\\Windows\\System32\\kernelbase.dll"}}},
			0x7ec254f31df879ec,
		},
		{
			&Kevent{Type: ktypes.CreateFile, PID: 4321, Kparams: Kparams{kparams.FilePath: {Name: kparams.FilePath, Type: kparams.DOSPath, Value: "C:\\Windows\\System32\\kernel32.dll"}}},
			0xb6380d9159ccd174,
		},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Equal(t, tt.key, tt.evt.PartialKey())
		})
	}
}

func TestCallstack(t *testing.T) {
	e := &Kevent{
		Type:      ktypes.CreateProcess,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       2,
		Name:      "CreateProcess",
		Timestamp: time.Now(),
		Category:  ktypes.Process,
	}

	e.Callstack.Init(9)
	assert.Equal(t, 9, cap(e.Callstack))

	e.Callstack.PushFrame(callstack.Frame{Addr: 0x2638e59e0a5, Offset: 0, Symbol: "?", Module: "unbacked"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0x7ffb313853b2, Offset: 0x10a, Symbol: "Java_java_lang_ProcessImpl_create", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0x7ffb3138592e, Offset: 0x3a2, Symbol: "Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0x7ffb5d8e61f4, Offset: 0x54, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNEL32.DLL"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0x7ffb5c1d0396, Offset: 0x66, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0xfffff8015662a605, Offset: 0x9125, Symbol: "setjmpex", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0xfffff801568e9c33, Offset: 0x2ef3, Symbol: "LpcRequestPort", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	e.Callstack.PushFrame(callstack.Frame{Addr: 0xfffff8015690b644, Offset: 0x45b4, Symbol: "ObDeleteCapturedInsertInfo", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})

	assert.True(t, e.Callstack.ContainsUnbacked())
	assert.Equal(t, 9, e.Callstack.Depth())
	assert.Equal(t, "0xfffff8015690b644 C:\\WINDOWS\\system32\\ntoskrnl.exe!ObDeleteCapturedInsertInfo+0x45b4|0xfffff801568e9c33 C:\\WINDOWS\\system32\\ntoskrnl.exe!LpcRequestPort+0x2ef3|0xfffff8015662a605 C:\\WINDOWS\\system32\\ntoskrnl.exe!setjmpex+0x9125|0x7ffb5c1d0396 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66|0x7ffb5d8e61f4 C:\\WINDOWS\\System32\\KERNEL32.DLL!CreateProcessW+0x54|0x7ffb5c1d0396 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x61|0x7ffb3138592e C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll!Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly+0x3a2|0x7ffb313853b2 C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll!Java_java_lang_ProcessImpl_create+0x10a|0x2638e59e0a5 unbacked!?", e.Callstack.String())
	assert.Equal(t, "KERNELBASE.dll|KERNEL32.DLL|KERNELBASE.dll|java.dll|unbacked", e.Callstack.Summary())

	uframe := e.Callstack.FinalUserFrame()
	require.NotNil(t, uframe)
	assert.Equal(t, "7ffb5c1d0396", uframe.Addr.String())
	assert.Equal(t, "CreateProcessW", uframe.Symbol)
	assert.Equal(t, "C:\\WINDOWS\\System32\\KERNELBASE.dll", uframe.Module)

	kframe := e.Callstack.FinalKernelFrame()
	require.NotNil(t, kframe)
	assert.Equal(t, "fffff8015690b644", kframe.Addr.String())
	assert.Equal(t, "ObDeleteCapturedInsertInfo", kframe.Symbol)
	assert.Equal(t, "C:\\WINDOWS\\system32\\ntoskrnl.exe", kframe.Module)
}
