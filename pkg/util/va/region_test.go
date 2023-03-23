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
	"golang.org/x/sys/windows"
	"unsafe"
)

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
