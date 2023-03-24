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

package va

import (
	"errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"unsafe"
)

func TestReadRegion(t *testing.T) {
	addr, err := getModuleBaseAddress(uint32(os.Getpid()))
	require.NoError(t, err)
	rgn, err := NewRegion(windows.CurrentProcess(), addr)
	require.NoError(t, err)
	require.True(t, rgn.Size(addr) > 0)

	size, b := rgn.Read(addr, uint(os.Getpagesize()), 0x100, false)
	require.True(t, size > 0)
	require.Len(t, b, os.Getpagesize())
	// verify it is the DOS header
	require.Equal(t, 'M', rune(b[0]))
	require.Equal(t, 'Z', rune(b[1]))

	var oldProtect uint32
	windows.VirtualProtectEx(windows.CurrentProcess(), addr, uintptr(rgn.Size(addr)), windows.PAGE_NOACCESS, &oldProtect)

	size, b = rgn.Read(addr, uint(os.Getpagesize()), 0x100, false)
	// shouldn't be able to read the region
	require.True(t, size == 0)
	require.Len(t, b, 0)
	windows.VirtualProtectEx(windows.CurrentProcess(), addr, uintptr(rgn.Size(addr)), oldProtect, &oldProtect)

	windows.VirtualProtectEx(windows.CurrentProcess(), addr, 4096, windows.PAGE_NOACCESS, &oldProtect)
	defer windows.VirtualProtectEx(windows.CurrentProcess(), addr, 4096, oldProtect, &oldProtect)

	noAccessRgn, err := NewRegion(windows.CurrentProcess(), addr)
	require.NoError(t, err)

	size, b = noAccessRgn.Read(addr, uint(os.Getpagesize()), 0x100, true)
	// force protection changing, so should be able to read the region
	require.True(t, size > 0)
	require.Len(t, b, os.Getpagesize())
}

func TestReadArea(t *testing.T) {
	addr, err := getModuleBaseAddress(uint32(os.Getpid()))
	require.NoError(t, err)

	area := ReadArea(windows.CurrentProcess(), addr, uint(os.Getpagesize()), 0x100, false)
	require.Len(t, area, os.Getpagesize())
	require.False(t, Zeroed(area))

	// allocate region with no access protection
	base, err := windows.VirtualAlloc(0, 1024, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	require.NoError(t, err)
	defer windows.VirtualFree(base, 1024, windows.MEM_RELEASE)
	var oldProtect uint32
	windows.VirtualProtectEx(windows.CurrentProcess(), base, 16, windows.PAGE_NOACCESS, &oldProtect)

	// it should read all bytes set to zero
	zeroArea := ReadArea(windows.CurrentProcess(), base, 4096, 0x100, false)
	require.Len(t, zeroArea, 4096)
	require.True(t, Zeroed(zeroArea))
}

func getModuleBaseAddress(pid uint32) (uintptr, error) {
	var moduleHandles [1024]windows.Handle
	var cbNeeded uint32
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	if err := windows.EnumProcessModules(proc, &moduleHandles[0], 1024, &cbNeeded); err != nil {
		return 0, err
	}
	for _, moduleHandle := range moduleHandles[:uintptr(cbNeeded)/unsafe.Sizeof(moduleHandles[0])] {
		var moduleInfo windows.ModuleInfo
		if err := windows.GetModuleInformation(proc, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo))); err != nil {
			return 0, err
		}
		return moduleInfo.BaseOfDll, nil
	}
	return 0, errors.New("no modules found")
}
