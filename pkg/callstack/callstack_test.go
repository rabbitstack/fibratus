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

package callstack

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCallstack(t *testing.T) {
	var callstack Callstack
	callstack.Init(9)

	assert.Equal(t, 9, cap(callstack))

	callstack.PushFrame(Frame{Addr: 0x2638e59e0a5, Offset: 0, Symbol: "?", Module: "unbacked"})
	callstack.PushFrame(Frame{Addr: 0x7ffb313853b2, Offset: 0x10a, Symbol: "Java_java_lang_ProcessImpl_create", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	callstack.PushFrame(Frame{Addr: 0x7ffb3138592e, Offset: 0x3a2, Symbol: "Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	callstack.PushFrame(Frame{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	callstack.PushFrame(Frame{Addr: 0x7ffb5d8e61f4, Offset: 0x54, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNEL32.DLL"})
	callstack.PushFrame(Frame{Addr: 0x7ffb5c1d0396, Offset: 0x66, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	callstack.PushFrame(Frame{Addr: 0xfffff8015662a605, Offset: 0x9125, Symbol: "setjmpex", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	callstack.PushFrame(Frame{Addr: 0xfffff801568e9c33, Offset: 0x2ef3, Symbol: "LpcRequestPort", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})
	callstack.PushFrame(Frame{Addr: 0xfffff8015690b644, Offset: 0x45b4, Symbol: "ObDeleteCapturedInsertInfo", Module: "C:\\WINDOWS\\system32\\ntoskrnl.exe"})

	assert.True(t, callstack.ContainsUnbacked())
	assert.Equal(t, 9, callstack.Depth())
	assert.Equal(t, "0xfffff8015690b644 C:\\WINDOWS\\system32\\ntoskrnl.exe!ObDeleteCapturedInsertInfo+0x45b4|0xfffff801568e9c33 C:\\WINDOWS\\system32\\ntoskrnl.exe!LpcRequestPort+0x2ef3|0xfffff8015662a605 C:\\WINDOWS\\system32\\ntoskrnl.exe!setjmpex+0x9125|0x7ffb5c1d0396 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66|0x7ffb5d8e61f4 C:\\WINDOWS\\System32\\KERNEL32.DLL!CreateProcessW+0x54|0x7ffb5c1d0396 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x61|0x7ffb3138592e C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll!Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly+0x3a2|0x7ffb313853b2 C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll!Java_java_lang_ProcessImpl_create+0x10a|0x2638e59e0a5 unbacked!?", callstack.String())
	assert.Equal(t, "KERNELBASE.dll|KERNEL32.DLL|KERNELBASE.dll|java.dll|unbacked", callstack.Summary())

	uframe := callstack.FinalUserFrame()
	require.NotNil(t, uframe)
	assert.Equal(t, "7ffb5c1d0396", uframe.Addr.String())
	assert.Equal(t, "CreateProcessW", uframe.Symbol)
	assert.Equal(t, "C:\\WINDOWS\\System32\\KERNELBASE.dll", uframe.Module)

	kframe := callstack.FinalKernelFrame()
	require.NotNil(t, kframe)
	assert.Equal(t, "fffff8015690b644", kframe.Addr.String())
	assert.Equal(t, "ObDeleteCapturedInsertInfo", kframe.Symbol)
	assert.Equal(t, "C:\\WINDOWS\\system32\\ntoskrnl.exe", kframe.Module)
}
