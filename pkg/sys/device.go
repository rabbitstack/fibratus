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
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// devSize specifies the initial size used to allocate the drivers info buffer
const devSize uint32 = 1024 * 256

// Driver contains device driver metadata for each driver found in
// the system.
type Driver struct {
	Path string
	Base uintptr
	Size uint32
}

// RTL_PROCESS_MODULE_INFORMATION mirrors the C struct
type RTL_PROCESS_MODULE_INFORMATION struct {
	Section          uintptr
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

// RTL_PROCESS_MODULES is the header returned by NtQuerySystemInformation
type RTL_PROCESS_MODULES struct {
	NumberOfModules uint32
	Modules         [1]RTL_PROCESS_MODULE_INFORMATION // variable-length, treated as start of array
}

// String returns the driver string representation.
func (d Driver) String() string {
	return fmt.Sprintf("Path: %s, Base: %x", d.Path, d.Base)
}

// EnumDevices returns metadata about device drivers encountered in the
// system. If device driver enumeration fails, an empty slice with device
// information is returned.
func EnumDevices() []Driver {
	var length uint32
	buf := make([]byte, devSize) // 256 KB initial guess

	for {
		err := windows.NtQuerySystemInformation(windows.SystemModuleInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &length)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW {
			buf = make([]byte, length)
			continue
		}
		if err != nil {
			return nil
		}

		// parse the buffer with driver information
		header := (*RTL_PROCESS_MODULES)(unsafe.Pointer(&buf[0]))
		count := header.NumberOfModules

		offset := unsafe.Offsetof(header.Modules)
		size := unsafe.Sizeof(RTL_PROCESS_MODULE_INFORMATION{})

		devs := make([]Driver, 0, count)

		for i := range count {
			m := (*RTL_PROCESS_MODULE_INFORMATION)(unsafe.Pointer(&buf[offset+uintptr(i)*size]))
			path := windows.ByteSliceToString(m.FullPathName[:])
			// normalize driver path
			path = strings.Replace(path, "\\SystemRoot", os.Getenv("SYSTEMROOT"), 1)
			dev := Driver{
				Base: m.ImageBase,
				Size: m.ImageSize,
				Path: path,
			}
			devs = append(devs, dev)
		}

		return devs
	}
}
