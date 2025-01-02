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

package threadcontext

import (
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"unsafe"
)

func TestDecode(t *testing.T) {
	ntdll, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)

	fn, err := windows.GetProcAddress(ntdll, "VirtualProtect")
	require.NoError(t, err)

	ctx := Context{
		Rip: uint64(fn),
	}

	const sz = int(unsafe.Sizeof(Context{}))
	b := (*(*[sz]byte)(unsafe.Pointer(&ctx)))[:]

	addr, err := windows.VirtualAlloc(0, uintptr(sz), windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)

	var n uintptr
	require.NoError(t, windows.WriteProcessMemory(windows.CurrentProcess(), addr, &b[0], uintptr(sz), &n))

	c := Decode(uint32(os.Getpid()), va.Address(addr))

	require.NotNil(t, c)
	require.Equal(t, fn, uintptr(c.Rip))
}

func TestIsParamOfFunc(t *testing.T) {
	var tests = []struct {
		f  string
		ok bool
	}{
		{"ZwContinue", true},
		{"RtlCaptureContext", true},
		{"CreateFile", false},
		{"CreateThread", false},
	}

	for _, tt := range tests {
		t.Run(tt.f, func(t *testing.T) {
			assert.Equal(t, tt.ok, IsParamOfFunc(tt.f))
		})
	}
}
