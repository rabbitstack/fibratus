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
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var drives = []string{
	"A",
	"B",
	"C",
	"D",
	"E",
	"F",
	"G",
	"H",
	"I",
	"J",
	"K",
	"L",
	"M",
	"N",
	"O",
	"P",
	"Q",
	"R",
	"S",
	"T",
	"U",
	"V",
	"W",
	"X",
	"Y",
	"Z"}

const FileFsDeviceInformationClass = 4

// FileFsDeviceInformation provides file system device information about
// the type of device object associated with a file object.
type FileFsDeviceInformation struct {
	// Type designates the type of underlying device.
	Type uint32
	// Characteristics represents device characteristics.
	Characteristics uint32
}

// GetLogicalDrives returns available device drive letters in the system.
func GetLogicalDrives() []string {
	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	devs := make([]string, 0)
	for _, drive := range drives {
		if bitmask&1 == 1 {
			devs = append(devs, drive+":")
		}
		bitmask >>= 1
	}
	return devs
}

// QueryDosDevice translates the DOS device name to hard disk drive letter.
func QueryDosDevice(drive string) (string, error) {
	dev := make([]uint16, windows.MAX_PATH)
	_, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(drive), &dev[0], windows.MAX_PATH)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(dev), nil
}

// PathIsDirectory determines if the provided path is a directory.
func PathIsDirectory(path string) bool {
	return pathIsDirectory(windows.StringToUTF16Ptr(path))
}

// GetMappedFile checks whether the specified address is within a memory-mapped file in the address
// space of the specified process. If so, the function returns the name of the memory-mapped file.
func GetMappedFile(process windows.Handle, addr uintptr) string {
	var size uint32 = windows.MAX_PATH
	n := make([]uint16, size)
	if GetMappedFileName(process, addr, &n[0], size) > 0 {
		return windows.UTF16ToString(n)
	}
	return ""
}

// WaitTimeout indicates the time-out interval
// elapsed, and the object's state is nonsignaled.
const WaitTimeout = 0x00000102

// ReadFile reads the file asynchronously with the specified number
// of bytes to read and the timeout after which the I/O operation
// is cancelled.
func ReadFile(path string, size int, timeout time.Duration) ([]byte, error) {
	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	// open file asynchronously
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(handle)

	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(event)

	var overlapped windows.Overlapped
	overlapped.HEvent = event

	buf := make([]byte, size) // chunk size
	var n uint32

	err = windows.ReadFile(handle, buf, &n, &overlapped)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return nil, err
	}
	// synchronous completion
	if err == nil && int(n) <= size {
		return buf[:n], nil
	}

	// wait for I/O operation to complete
	wait, err := windows.WaitForSingleObject(event, uint32(timeout.Milliseconds()))
	switch wait {
	case windows.WAIT_FAILED:
		return nil, err
	case WaitTimeout:
		// cancel the I/O
		_ = windows.CancelIoEx(handle, &overlapped)

		// must wait until cancellation completes
		_, _ = windows.WaitForSingleObject(event, 1000)
		err = windows.GetOverlappedResult(handle, &overlapped, &n, false)
		if err == windows.ERROR_OPERATION_ABORTED {
			return nil, fmt.Errorf("timeout reading file %s", path)
		}
		return nil, err
	}

	// get the result
	err = windows.GetOverlappedResult(handle, &overlapped, &n, false)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
