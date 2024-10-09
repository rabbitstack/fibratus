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

package sys

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"unsafe"
)

const (
	// InvalidProcessID represents the value of an invalid process identifier
	InvalidProcessID uint32 = 0xffffffff
	// ProcessStatusStillActive represents the status of the running process
	ProcessStatusStillActive uint32 = 259
)

// ProcessProtectionInformation is the information class that returns a
// value indicating the type of protected process and the protected process
// signer.
const ProcessProtectionInformation = 61

// PsProtection describes the process protection attributes.
type PsProtection struct {
	// S is the C union field describing protection attributes.
	//	union {
	//		struct {
	//			PS_PROTECTED_TYPE Type : 3;
	//			BOOLEAN Audit : 1;
	//			PS_PROTECTED_SIGNER Signer : 4;
	//	 } s;
	// }
	S     byte
	Level byte
}

// IsProtected determines if the process has the protected flag.
// The protected mask is stored in the bit field comprising the
// bits 1 to 3.
func (pp PsProtection) IsProtected() bool {
	return int((pp.S>>1)&((1<<3)-1)) != 0
}

// QueryInformationProcess consults the specified process information class and returns
// a pointer to the structure containing process information.
func QueryInformationProcess[C any](proc windows.Handle, class int32) (*C, error) {
	var c C
	var s uint32
	n := make([]byte, unsafe.Sizeof(c))
	err := windows.NtQueryInformationProcess(proc, class, unsafe.Pointer(&n[0]), uint32(len(n)), &s)
	if err != nil {
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW {
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

// ReadProcessMemory reads from the process virtual address space starting at specified address.
func ReadProcessMemory[S any](proc windows.Handle, addr uintptr) (*S, error) {
	var s S
	b := make([]byte, unsafe.Sizeof(s))
	err := windows.ReadProcessMemory(proc, addr, &b[0], uintptr(len(b)), nil)
	if err != nil {
		return nil, err
	}
	return (*S)(unsafe.Pointer(&b[0])), nil
}

// IsProcessRunning determines whether the process is in a running state.
func IsProcessRunning(proc windows.Handle) bool {
	var exitcode uint32
	err := windows.GetExitCodeProcess(proc, &exitcode)
	if err != nil {
		return false
	}
	return exitcode == ProcessStatusStillActive
}

// IsProcessPackaged determines if the process is packaged by trying
// to resolve the package identifier.
func IsProcessPackaged(proc windows.Handle) bool {
	var n uint32
	err := GetPackageID(proc, &n, 0)
	if err == windows.ERROR_INSUFFICIENT_BUFFER {
		b := make([]byte, n)
		err = GetPackageID(proc, &n, uintptr(unsafe.Pointer(&b[0])))
	}
	return err == nil
}

// IsWindowsService reports whether the process is currently executing
// as a Windows service.
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	return isSvc && err == nil
}
