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

package evasion

import (
	"testing"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestIndirectSyscall(t *testing.T) {
	var tests = []struct {
		evt     *event.Event
		matches bool
	}{
		{&event.Event{
			Type:      event.CreateFile,
			Tid:       2484,
			PID:       859,
			CPU:       1,
			Seq:       2,
			Name:      "CreateFile",
			Timestamp: time.Now(),
			Category:  event.File,
			Params: event.Params{
				params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
				params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
				params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
				params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
			},
			PS: &pstypes.PS{
				Modules: []pstypes.Module{
					{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: getNtdllAddress(), DefaultBaseAddress: getNtdllAddress()},
					{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
					{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
				},
			},
			Callstack: callstackFromFrames(
				callstack.Frame{Addr: 0xf259de, Module: "unbacked", Symbol: "?"},
				callstack.Frame{Addr: getNtdllProcAddress("NtCreateUserProcess"), ModuleAddress: getNtdllAddress(), Module: "C:\\Windows\\System32\\ntdll.dll", Symbol: "ZwCreateFile"},
				callstack.Frame{Addr: 0xfffff807e228c555, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "setjmpex"},
				callstack.Frame{Addr: 0xfffff807e264805c, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "ObOpenObjectByPointerWithTag"}),
		}, true},
		{&event.Event{
			Type:      event.SetThreadContext,
			Tid:       2484,
			PID:       859,
			CPU:       1,
			Seq:       2,
			Name:      "SetThreadContext",
			Timestamp: time.Now(),
			Category:  event.Thread,
			PS: &pstypes.PS{
				Modules: []pstypes.Module{
					{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: getNtdllAddress(), DefaultBaseAddress: getNtdllAddress()},
					{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
					{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
				},
			},
			Callstack: callstackFromFrames(
				callstack.Frame{Addr: 0xf259de, Module: "unbacked", Symbol: "?"},
				callstack.Frame{Addr: 0x7ffe4fda6e3b, Module: "C:\\Windows\\System32\\KernelBase.dll", Symbol: "SetThreadContext"},
				callstack.Frame{Addr: getNtdllProcAddress("ZwSetContextThread") + 20, ModuleAddress: getNtdllAddress(), Module: "C:\\Windows\\System32\\ntdll.dll", Symbol: "ZwSetContextThread"},
				callstack.Frame{Addr: 0xfffff807e228c555, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "setjmpex"},
				callstack.Frame{Addr: 0xfffff807e264805c, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "ObOpenObjectByPointerWithTag"}),
		}, false},
		{&event.Event{
			Type:      event.CreateFile,
			Tid:       2484,
			PID:       859,
			CPU:       1,
			Seq:       2,
			Name:      "CreateFile",
			Timestamp: time.Now(),
			Category:  event.File,
			Params: event.Params{
				params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
				params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
				params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
				params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
			},
			Callstack: callstackFromFrames(
				callstack.Frame{Addr: 0xf259de, Module: "unbacked", Symbol: "?"},
				callstack.Frame{Addr: 0x7ffe4fda6e3b, Module: "C:\\Windows\\System32\\KernelBase.dll", Symbol: "SetThreadContext"},
				callstack.Frame{Addr: getNtdllProcAddress("ZwQueryAttributesFile"), ModuleAddress: getNtdllAddress(), Module: "C:\\Windows\\System32\\ntdll.dll", Symbol: "ZwQueryAttributesFile"},
				callstack.Frame{Addr: 0xfffff807e228c555, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "setjmpex"},
				callstack.Frame{Addr: 0xfffff807e264805c, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "ObOpenObjectByPointerWithTag"}),
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Name, func(t *testing.T) {
			eva := NewIndirectSyscall()
			matches, err := eva.Eval(tt.evt)
			require.NoError(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}

func getNtdllAddress() va.Address {
	var moduleHandles [1024]windows.Handle
	var cbNeeded uint32
	proc, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, windows.GetCurrentProcessId())
	if err != nil {
		return 0
	}
	if err := windows.EnumProcessModules(proc, &moduleHandles[0], 1024, &cbNeeded); err != nil {
		return 0
	}
	moduleHandle := moduleHandles[1]
	var moduleInfo windows.ModuleInfo
	if err := windows.GetModuleInformation(proc, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo))); err != nil {
		return 0
	}
	return va.Address(moduleInfo.BaseOfDll)
}

func getNtdllProcAddress(procname string) va.Address {
	var handle windows.Handle
	if err := windows.GetModuleHandleEx(sys.ModuleHandleFromAddress, (*uint16)(unsafe.Pointer(getNtdllAddress().Uintptr())), &handle); err != nil {
		panic(err)
	}
	addr, err := windows.GetProcAddress(handle, procname)
	if err != nil {
		panic(err)
	}
	defer windows.CloseHandle(handle)
	return va.Address(addr)
}
