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

package object

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"syscall"
	"unsafe"
)

var (
	nt = syscall.NewLazyDLL("ntdll")

	ntQueryObject = nt.NewProc("NtQueryObject")
)

// InformationClass is the type alias for object information classes.
type InformationClass uint8

const (
	// NameInformationClass returns the object name information.
	NameInformationClass InformationClass = 1
	// TypeInformationClass returns the object type information.
	TypeInformationClass InformationClass = 2
	// TypesInformationClass returns handle object types.
	TypesInformationClass InformationClass = 3
	// SystemHandleInformationClass returns allocated system handles.
	SystemHandleInformationClass = 16
	// SystemExtendedHandleInformation returns extended allocated system handles.
	SystemExtendedHandleInformation = 64
)

// Query retrieves specified information for the handle reference.
func Query(handle handle.Handle, klass InformationClass, buf []byte) (uint32, error) {
	size := uint32(len(buf))
	status, _, _ := ntQueryObject.Call(
		uintptr(handle),
		uintptr(klass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
	)
	if status != 0 {
		if status == winerrno.StatusInfoLengthMismatch || status == winerrno.StatusBufferTooSmall {
			return size, errors.ErrNeedsReallocateBuffer
		}
		return size, fmt.Errorf("NtQueryObject failed with status code 0x%X", status)
	}
	return size, nil
}
