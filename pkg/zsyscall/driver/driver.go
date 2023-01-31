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

package driver

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// AddrsSize specifies the initial size used to allocate the driver base addresses
const AddrsSize = 1024

var (
	psapi = syscall.NewLazyDLL("psapi.dll")

	enumDeviceDrivers       = psapi.NewProc("EnumDeviceDrivers")
	getDeviceDriverFileName = psapi.NewProc("GetDeviceDriverFileNameW")
)

// Driver contains device driver metadata for each driver found in
// the system.
type Driver struct {
	Filename string
}

// String returns the driver string representation.
func (d Driver) String() string {
	return fmt.Sprintf("File: %s", d.Filename)
}

// EnumDevices returns metadata about device drivers encountered in the
// system. If device driver enumeration fails, an empty slice with device
// information is returned.
func EnumDevices() []Driver {
	needed := 0
	addrs := make([]uintptr, AddrsSize)
	rc, _, _ := enumDeviceDrivers.Call(
		uintptr(unsafe.Pointer(&addrs[0])),
		AddrsSize,
		uintptr(unsafe.Pointer(&needed)),
	)
	if rc == 0 {
		return nil
	}
	// base image size greater than initial allocation
	if needed > len(addrs) {
		addrs = make([]uintptr, needed)
		rc, _, _ := enumDeviceDrivers.Call(
			uintptr(unsafe.Pointer(&addrs[0])),
			uintptr(needed),
			uintptr(unsafe.Pointer(&needed)),
		)
		if rc == 0 {
			return nil
		}
	}
	// resize to get the number of drivers
	if needed/8 < len(addrs) {
		addrs = addrs[:needed/8]
	}
	drivers := make([]Driver, len(addrs))
	for i, addr := range addrs {
		drv := Driver{}
		filename := make([]uint16, syscall.MAX_PATH)
		if l, _, _ := getDeviceDriverFileName.Call(
			addr,
			uintptr(unsafe.Pointer(&filename[0])),
			syscall.MAX_PATH); l > 0 {
			f := syscall.UTF16ToString(filename)
			drv.Filename = strings.Replace(f, "\\SystemRoot", os.Getenv("SYSTEMROOT"), -1)
		}
		drivers[i] = drv
	}
	return drivers
}
