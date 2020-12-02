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

package file

import (
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32")
	shlwapi  = syscall.NewLazyDLL("shlwapi")
	nt       = syscall.NewLazyDLL("ntdll")

	getLogicalDrives = kernel32.NewProc("GetLogicalDrives")
	queryDosDevice   = kernel32.NewProc("QueryDosDeviceW")
	pathIsDirectory  = shlwapi.NewProc("PathIsDirectoryW")

	ntQueryVolumeInformationFile = nt.NewProc("NtQueryVolumeInformationFile")

	drives = []string{
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
)

const (
	fsDeviceInformation = 4
)

// GetLogicalDrives returns available device drives in the system.
func GetLogicalDrives() []string {
	r, _, _ := getLogicalDrives.Call()
	bitmask := uint32(r)
	devs := make([]string, 0)
	for _, drive := range drives {
		if bitmask&1 == 1 {
			devs = append(devs, drive+":")
		}
		bitmask >>= 1
	}
	return devs
}

// QueryVolumeInfo obtains device information for the specified file handle.
func QueryVolumeInfo(fd uintptr) (*DevInfo, error) {
	var (
		iosb ioStatusBlock
		di   DevInfo
	)
	_, _, err := ntQueryVolumeInformationFile.Call(
		fd,
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&di)),
		uintptr(unsafe.Sizeof(di)),
		uintptr(fsDeviceInformation),
	)
	if err != nil && err != syscall.Errno(0) {
		return nil, os.NewSyscallError("NtQueryVolumeInformationFile", err)
	}
	return &di, nil
}

// QueryDosDevice translates the DOS device name to hard disk drive letter.
func QueryDosDevice(drive string) (string, error) {
	dev := make([]uint16, syscall.MAX_PATH)
	errno, _, err := queryDosDevice.Call(
		uintptr(unsafe.Pointer(utf16.StringToUTF16Ptr(drive))),
		uintptr(unsafe.Pointer(&dev[0])),
		uintptr(syscall.MAX_PATH),
	)
	if winerrno.Errno(errno) == winerrno.Success {
		return "", os.NewSyscallError("QueryDosDevice", err)
	}
	return syscall.UTF16ToString(dev), nil
}

// IsPathDirectory indicates if path is a valid directory.
func IsPathDirectory(path string) bool {
	isDir, _, _ := pathIsDirectory.Call(uintptr(unsafe.Pointer(utf16.StringToUTF16Ptr(path))))
	return isDir > 0
}
