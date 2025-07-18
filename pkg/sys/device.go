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
	"syscall"
	"unsafe"
)

// DevSize specifies the initial size used to allocate the driver base addresses
const DevSize = 1024

// Driver contains device driver metadata for each driver found in
// the system.
type Driver struct {
	Filename string
	Addr     uintptr
}

// String returns the driver string representation.
func (d Driver) String() string {
	return fmt.Sprintf("File: %s", d.Filename)
}

// EnumDevices returns metadata about device drivers encountered in the
// system. If device driver enumeration fails, an empty slice with device
// information is returned.
func EnumDevices() []Driver {
	needed := uint32(0)
	addrs := make([]uintptr, DevSize)
	err := EnumDeviceDrivers(uintptr(unsafe.Pointer(&addrs[0])), DevSize, &needed)
	if err != nil {
		return nil
	}
	// base image size greater than initial allocation
	if needed > uint32(len(addrs)) {
		addrs = make([]uintptr, needed)
		err := EnumDeviceDrivers(uintptr(unsafe.Pointer(&addrs[0])), needed, &needed)
		if err != nil {
			return nil
		}
	}
	// resize to get the number of drivers
	if needed/8 < uint32(len(addrs)) {
		addrs = addrs[:needed/8]
	}
	drivers := make([]Driver, len(addrs))
	for i, addr := range addrs {
		drv := Driver{
			Addr: addr,
		}
		filename := make([]uint16, syscall.MAX_PATH)
		n := GetDeviceDriverFileName(addr, &filename[0], syscall.MAX_PATH)
		if n == 0 {
			continue
		}
		dev := syscall.UTF16ToString(filename)
		drv.Filename = strings.Replace(dev, "\\SystemRoot", os.Getenv("SYSTEMROOT"), 1)
		drivers[i] = drv
	}
	return drivers
}
