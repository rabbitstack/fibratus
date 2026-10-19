//go:build windows

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
	"errors"
	"runtime"
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

// ErrSkipped signals the file is offline or a cloud placeholder and was not read.
var ErrFileSkipped = errors.New("file is offline or a cloud placeholder")

// ErrTimeout signals that the timeout elapsed while trying to read the file.
var ErrFileTimeout = errors.New("timeout reading file")

// ReadFile reads the file asynchronously with the specified number
// of bytes to read and the timeout after which the I/O operation
// is cancelled.
func ReadFile(path string, size int, timeout time.Duration) ([]byte, error) {
	return ReadFileWithPredicate(path, size, 0, timeout, nil)
}

// ReadFileWithPredicate opens the file once and reads its first probeSize bytes. If
// accept predicate is non-nil and returns an error, the read stops there and that
// error is returned. Otherwise the rest of the file is read, up to size bytes in total.
// The buffer is never larger than the file.
func ReadFileWithPredicate(path string, size, probeSize int, timeout time.Duration, accept func(head []byte) error) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	// open file asynchronously
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_OPEN_NO_RECALL,
		0,
	)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_OFFLINE|windows.FILE_ATTRIBUTE_RECALL_ON_OPEN|windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0 {
		return nil, ErrFileSkipped
	}
	fsize := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	total := size
	if fsize < int64(total) {
		total = int(fsize)
	}
	if total == 0 {
		return []byte{}, nil
	}

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(ev)

	first := total
	if accept != nil && probeSize > 0 && probeSize < first {
		first = probeSize
	}

	head := make([]byte, first)
	n, err := readFileAt(handle, ev, head, 0, timeout)
	if err != nil {
		return nil, err
	}

	head = head[:n]
	if accept != nil {
		if err := accept(head); err != nil {
			return nil, err
		}
	}
	if total <= first || n < first {
		return head, nil
	}

	buf := make([]byte, total)
	copy(buf, head)
	m, err := readFileAt(handle, ev, buf[n:], uint64(n), timeout)
	if err != nil {
		return nil, err
	}
	return buf[:n+m], nil
}

// readFileAt performs one overlapped read. It never returns while the kernel can
// still write into buf.
func readFileAt(h, ev windows.Handle, buf []byte, off uint64, timeout time.Duration) (int, error) {
	var ov windows.Overlapped
	ov.HEvent = ev
	ov.Offset = uint32(off)
	ov.OffsetHigh = uint32(off >> 32)
	_ = windows.ResetEvent(ev)

	var n uint32
	err := windows.ReadFile(h, buf, &n, &ov)
	switch err {
	case nil:
		return int(n), nil
	case windows.ERROR_HANDLE_EOF:
		return 0, nil
	case windows.ERROR_IO_PENDING:
	default:
		return 0, err
	}

	wait, werr := windows.WaitForSingleObject(ev, uint32(timeout.Milliseconds()))
	if wait != windows.WAIT_OBJECT_0 {
		_ = windows.CancelIoEx(h, &ov)
		// block until the kernel is done with buf
		_ = windows.GetOverlappedResult(h, &ov, &n, true)
		runtime.KeepAlive(buf)
		if wait == WaitTimeout {
			return 0, ErrFileTimeout
		}
		return 0, werr
	}
	if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
		if err == windows.ERROR_HANDLE_EOF {
			return 0, nil
		}
		return 0, err
	}
	return int(n), nil
}
