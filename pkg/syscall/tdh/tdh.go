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

package tdh

import (
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"os"
	"syscall"
	"unsafe"
)

var (
	tdh = syscall.NewLazyDLL("tdh.dll")

	tdhGetEventInformation = tdh.NewProc("TdhGetEventInformation")
	tdhGetPropertySize     = tdh.NewProc("TdhGetPropertySize")
	tdhGetProperty         = tdh.NewProc("TdhGetProperty")
)

// GetEventInformation retrieves metadata about an event. It receives a buffer that to allocate
// `TraceEventInfo` structure.
func GetEventInformation(evt *etw.EventRecord, buffer []byte, size uint32) error {
	errno, _, err := tdhGetEventInformation.Call(
		uintptr(unsafe.Pointer(evt)),
		0,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	switch winerrno.Errno(errno) {
	case winerrno.Success:
		return nil
	case winerrno.InsufficientBuffer:
		return kerrors.ErrInsufficentBuffer
	case winerrno.NotFound:
		return kerrors.ErrEventSchemaNotFound
	default:
		return os.NewSyscallError("TdhGetEventInformation", err)
	}
}

// GetPropertySize retrieves the size of one or more property values in the event data.
func GetPropertySize(evt *etw.EventRecord, descriptor *PropertyDataDescriptor) (uint32, error) {
	var size uint32
	errno, _, err := tdhGetPropertySize.Call(
		uintptr(unsafe.Pointer(evt)),
		0,
		0,
		1,
		uintptr(unsafe.Pointer(descriptor)),
		uintptr(unsafe.Pointer(&size)),
	)
	if winerrno.Errno(errno) != winerrno.Success {
		return uint32(0), os.NewSyscallError("TdhGetPropertySize", err)
	}
	return size, nil
}

// GetProperty retrieves a property value from the event data.
func GetProperty(evt *etw.EventRecord, descriptor *PropertyDataDescriptor, size uint32, buffer []byte) error {
	errno, _, err := tdhGetProperty.Call(
		uintptr(unsafe.Pointer(evt)),
		0,
		0,
		1,
		uintptr(unsafe.Pointer(descriptor)),
		uintptr(size),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if winerrno.Errno(errno) != winerrno.Success {
		return os.NewSyscallError("TdhGetProperty", err)
	}
	return nil
}
