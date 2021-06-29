// +build windows

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

package sys

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/object"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"syscall"
	"unsafe"
)

var (
	native = syscall.NewLazyDLL("ntdll")

	ntQuerySystemInformation = native.NewProc("NtQuerySystemInformation")
	rtlNtStatusToDosError    = native.NewProc("RtlNtStatusToDosError")
)

// QuerySystemInformation retrieves system low-level information.
func QuerySystemInformation(class object.InformationClass, buf []byte) (uint32, error) {
	size := uint32(0)
	status, _, _ := ntQuerySystemInformation.Call(uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)))
	if status != 0 {
		if status == winerrno.StatusInfoLengthMismatch || status == winerrno.StatusBufferTooSmall {
			return size, errors.ErrNeedsReallocateBuffer
		}
		return size, fmt.Errorf("NtQuerySystemInformation failed with status code 0x%X", status)
	}
	return size, nil
}

// CodeFromNtStatus converts the specified NTSTATUS code to its equivalent system error code.
func CodeFromNtStatus(status uint32) uint32 {
	code, _, _ := rtlNtStatusToDosError.Call(uintptr(status))
	return uint32(code)
}
