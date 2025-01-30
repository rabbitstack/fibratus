/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

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

	e.Callstack.PushFrame(Frame{Addr: 0x2638e59e0a5, Offset: 0, Symbol: "?", Module: "unbacked"})
	e.Callstack.PushFrame(Frame{Addr: 0x7ffb313853b2, Offset: 0x10a, Symbol: "Java_java_lang_ProcessImpl_create", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	e.Callstack.PushFrame(Frame{Addr: 0x7ffb3138592e, Offset: 0x3a2, Symbol: "Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	e.Callstack.PushFrame(Frame{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	e.Callstack.PushFrame(Frame{Addr: 0x7ffb5d8e61f4, Offset: 0x54, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNEL32.DLL"})
	e.Callstack.PushFrame(Frame{Addr: 0x7ffb5c1d0396, Offset: 0x66, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	e.Callstack.PushFrame(Frame{Addr: 0xfffff8015662a605, Offset: 0x9125, Symbol: "setjmpex", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	e.Callstack.PushFrame(Frame{Addr: 0xfffff801568e9c33, Offset: 0x2ef3, Symbol: "LpcRequestPort", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	e.Callstack.PushFrame(Frame{Addr: 0xfffff8015690b644, Offset: 0x45b4, Symbol: "ObDeleteCapturedInsertInfo", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})

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

func TestCallstackDecorator(t *testing.T) {
	q := NewQueue(50, false, true)
	cd := NewCallstackDecorator(q)

	e := &Kevent{
		Type:      ktypes.CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       2,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  ktypes.File,
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	e1 := &Kevent{
		Type:      ktypes.CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       3,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  ktypes.File,
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\kernel32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	cd.Push(e)
	cd.Push(e1)

	assert.True(t, cd.deq.Len() == 2)

	sw := &Kevent{
		Type:      ktypes.StackWalk,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       4,
		Name:      "StackWalk",
		Timestamp: time.Now(),
		Kparams: Kparams{
			kparams.Callstack: {Name: kparams.Callstack, Type: kparams.Slice, Value: []va.Address{0x7ffb5eb70dc4, 0x7ffb5c191deb, 0x7ffb3138592e}},
		},
	}

	evt := cd.Pop(sw)
	assert.True(t, cd.deq.Len() == 1)
	assert.Equal(t, ktypes.CreateFile, evt.Type)
	assert.True(t, evt.Kparams.Contains(kparams.Callstack))
	assert.Equal(t, "C:\\Windows\\system32\\user32.dll", evt.GetParamAsString(kparams.FilePath))
}

func init() {
	maxDequeFlushPeriod = time.Second * 2
	flusherInterval = time.Second
}

func TestCallstackDecoratorFlush(t *testing.T) {
	q := NewQueue(50, false, true)
	q.RegisterListener(&DummyListener{})
	cd := NewCallstackDecorator(q)
	defer cd.Stop()

	e := &Kevent{
		Type:      ktypes.CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       2,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  ktypes.File,
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	cd.Push(e)
	assert.True(t, cd.deq.Len() == 1)
	time.Sleep(time.Millisecond * 3100)

	evt := <-q.Events()
	assert.True(t, cd.deq.Len() == 0)
	assert.Equal(t, ktypes.CreateFile, evt.Type)
	assert.False(t, evt.Kparams.Contains(kparams.Callstack))
}
