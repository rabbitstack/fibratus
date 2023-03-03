//go:build windows
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

package fs

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/zsyscall"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const (
	directoryFile = 0x00000001 // file being created or opened is a directory file

	deviceCDROM      = 0x00000002
	deviceCDROMFs    = 0x00000003
	deviceController = 0x00000004
	deviceDatalink   = 0x00000005
	deviceDFS        = 0x00000006
	deviceDisk       = 0x00000007
	deviceDiskFs     = 0x00000008

	devMailslot  = 0x0000000c
	devNamedPipe = 0x00000011

	devConsole = 0x00000050
)

// queryVolumeCalls represents the number of times the query volume function was called
var queryVolumeCalls = expvar.NewInt("file.query.volume.info.calls")

// GetFileType returns the underlying file type. The opts parameter corresponds to the NtCreateFile CreateOptions argument
// that specifies the options to be applied when creating or opening the file.
func GetFileType(filename string, opts uint32) FileType {
	if filename == "" {
		return Other
	}
	// if the CreateOptions argument of the NtCreateFile syscall has been invoked
	// with the FILE_DIRECTORY_FILE flag, it is likely that the target file object
	// is a directory. We ensure that by calling the API function for checking whether
	// the path name is truly a directory
	if (opts&directoryFile) != 0 && zsyscall.PathIsDirectory(filename) {
		return Directory
	}
	// FILE_DIRECTORY_FILE flag only gives us a hint on the CreateFile op outcome. If this flag is
	// not present in the argument but the file is a directory, we can apply some simple heuristics
	// like checking the extension/suffix, even though they are not bullet-proof
	if filename[:len(filename)-1] == "\\" || filepath.Ext(filename) == "" {
		return Directory
	}
	// non directory file can be a regular file, logical, virtual or physical device or a volume.
	// If the filename doesn't start with a drive letter it's probably not a regular
	// file since we already have mapped the DOS name to drive letter
	if !strings.HasPrefix(filename, "\\Device") {
		return Regular
	}
	// if the filename contains the HardiskVolume string then we assume it is a file. This
	// could happen if we fail to resolve the DOS name
	if strings.HasPrefix(filename, "\\Device\\HarddiskVolume") {
		return Regular
	}
	// logical, virtual, physical device or a volume
	// obtain the device type that is linked to this file object
	return getFileTypeFromVolumeInfo(filename)
}

func getFileTypeFromVolumeInfo(filename string) FileType {
	f, err := os.Open(filename)
	if err != nil {
		return Other
	}
	defer f.Close()

	queryVolumeCalls.Add(1)

	var (
		iosb windows.IO_STATUS_BLOCK
		dev  zsyscall.FileFsDeviceInformation
	)
	err = zsyscall.NtQueryVolumeInformationFile(
		windows.Handle(f.Fd()),
		&iosb,
		uintptr(unsafe.Pointer(&dev)),
		uint32(unsafe.Sizeof(dev)),
		zsyscall.FileFsDeviceInformationClass,
	)
	if err != nil {
		return Other
	}
	switch dev.Type {
	case deviceCDROM, deviceCDROMFs, deviceController,
		deviceDatalink, deviceDFS, deviceDisk, deviceDiskFs:
		if zsyscall.PathIsDirectory(filename) {
			return Directory
		}
		return Regular
	case devConsole:
		return Console
	case devMailslot:
		return Mailslot
	case devNamedPipe:
		return Pipe
	default:
		return Other
	}
}
