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

package zsyscall

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	// InvalidProcessPid represents the value of an invalid process identifier
	InvalidProcessPid uint32 = 0xffffffff
	// ProcessStatusStillActive represents the status of the running process
	ProcessStatusStillActive uint32 = 259
)

func QueryInformationProcess[C any](proc windows.Handle, class int32) (*C, error) {
	var c C
	var s uint32
	n := make([]byte, unsafe.Sizeof(c))
	err := windows.NtQueryInformationProcess(proc, class, unsafe.Pointer(&n[0]), uint32(len(n)), &s)
	if err != nil {
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL {
			n = make([]byte, s)
			err := windows.NtQueryInformationProcess(proc, class, unsafe.Pointer(&n[0]), uint32(len(n)), &s)
			if err != nil {
				return nil, err
			}
			return (*C)(unsafe.Pointer(&n[0])), nil
		}
		return nil, err
	}
	return (*C)(unsafe.Pointer(&n[0])), nil
}

func ReadProcessMemory[S any](proc windows.Handle, addr uintptr) (*S, error) {
	var s S
	b := make([]byte, unsafe.Sizeof(s))
	err := windows.ReadProcessMemory(proc, addr, &b[0], uintptr(len(b)), nil)
	if err != nil {
		return nil, err
	}
	return (*S)(unsafe.Pointer(&b[0])), nil
}

func IsProcessRunning(proc windows.Handle) bool {
	var exitcode uint32
	err := windows.GetExitCodeProcess(proc, &exitcode)
	if err != nil {
		return false
	}
	return exitcode == ProcessStatusStillActive
}
