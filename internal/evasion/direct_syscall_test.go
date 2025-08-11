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
	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDirectSyscall(t *testing.T) {
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
			Callstack: callstackFromFrames(
				callstack.Frame{Addr: 0xf259de, Module: "unbacked", Symbol: "?"},
				callstack.Frame{Addr: 0x7ffe4fda6e3b, Module: "C:\\Windows\\System32\\KernelBase.dll", Symbol: "SetThreadContext"},
				callstack.Frame{Addr: 0xfffff807e228c555, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "setjmpex"},
				callstack.Frame{Addr: 0xfffff807e264805c, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "ObOpenObjectByPointerWithTag"}),
		}, true},
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
				callstack.Frame{Addr: 0x7ffe52942b24, Module: "C:\\Windows\\System32\\ntdll.dll", Symbol: "ZwSetContextThread"},
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
				callstack.Frame{Addr: 0x7ffe52942b24, Module: "C:\\Windows\\System32\\wow64win.dll", Symbol: "SetContextThread"},
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
				callstack.Frame{Addr: 0x7ffe52942b24, Module: "unbacked", Symbol: "?"},
				callstack.Frame{Addr: 0xfffff807e228c555, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "setjmpex"},
				callstack.Frame{Addr: 0xfffff807e264805c, Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe", Symbol: "ObOpenObjectByPointerWithTag"}),
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Name, func(t *testing.T) {
			eva := NewDirectSyscall()
			matches, err := eva.Eval(tt.evt)
			require.NoError(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}

func callstackFromFrames(frames ...callstack.Frame) callstack.Callstack {
	var c callstack.Callstack
	for _, frame := range frames {
		c.PushFrame(frame)
	}
	return c
}
