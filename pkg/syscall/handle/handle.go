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

package handle

import (
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	closeHandle     = kernel32.NewProc("CloseHandle")
	duplicateHandle = kernel32.NewProc("DuplicateHandle")
)

// Handle represents the handle type.
type Handle uintptr

// DuplicateAccess is the enum for handle duplicate access flags.
type DuplicateAccess uint32

const (
	// ThreadQueryAccess determines that handle duplication requires the ability to query thread info.
	ThreadQueryAccess DuplicateAccess = 0x0040
	// ProcessQueryAccess determines that handle duplication requires the ability to query process info.
	ProcessQueryAccess DuplicateAccess = 0x1000
	// ReadControlAccess specifies the ability to query the security descriptor.
	ReadControlAccess DuplicateAccess = 0x00020000
	// SemaQueryAccess is the duplicate access type required for synchronization objects such as mutants.
	SemaQueryAccess DuplicateAccess = 0x0001
	// AllAccess doesn't specify the access mask.
	AllAccess DuplicateAccess = 0
)

// IsValid determines if handle instance if valid.
func (handle Handle) IsValid() bool {
	return handle != ^Handle(0)
}

// Close disposes the underlying handle object.
func (handle Handle) Close() {
	if handle == 0 {
		return
	}
	_, _, _ = closeHandle.Call(uintptr(handle))
}

// Duplicate duplicates an object handle in the caller address's space.
func (handle Handle) Duplicate(src, dest Handle, access DuplicateAccess) (Handle, error) {
	var destHandle Handle
	errno, _, err := duplicateHandle.Call(
		uintptr(src),
		uintptr(handle),
		uintptr(dest),
		uintptr(unsafe.Pointer(&destHandle)),
		uintptr(access),
		0,
		0,
	)
	if winerrno.Errno(errno) != winerrno.Success {
		return destHandle, nil
	}
	return Handle(0), os.NewSyscallError("DuplicateHandle", err)
}
