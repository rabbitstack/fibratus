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

package process

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	native   = syscall.NewLazyDLL("ntdll.dll")

	openProcess               = kernel32.NewProc("OpenProcess")
	queryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	readProcessMemory         = kernel32.NewProc("ReadProcessMemory")
	ntQueryInformationProcess = native.NewProc("NtQueryInformationProcess")
	getProcessTimes           = kernel32.NewProc("GetProcessTimes")
	getProcessIdOfThread      = kernel32.NewProc("GetProcessIdOfThread")
	getExitCodeProcess        = kernel32.NewProc("GetExitCodeProcess")
)

// DesiredAccess defines the type alias for process's access modifiers
type DesiredAccess uint32

const (
	procStatusStillActive = 259
	// QueryInformation is required to retrieve certain information about a process, such as its token, exit code, and priority class
	QueryInformation DesiredAccess = 0x0400
	// QueryLimitedInformation is required to get certain information about process, such as process's image name
	QueryLimitedInformation DesiredAccess = 0x1000
	// VMRead is required to read memory in a process
	VMRead DesiredAccess = 0x0010
	// DupHandle lets duplicate handles of the target process
	DupHandle DesiredAccess = 0x0040
)

// InfoClassFlags defines the type for process's info class
type InfoClassFlags uint8

const (
	// BasicInformationClass returns basic process's information
	BasicInformationClass  InfoClassFlags = 0
	HandleInformationClass InfoClassFlags = 51
)

// Open acquires an handle from the running process.
func Open(access DesiredAccess, inheritHandle bool, processID uint32) (handle.Handle, error) {
	var inherit uint8
	if inheritHandle {
		inherit = 1
	} else {
		inherit = 0
	}
	h, _, err := openProcess.Call(uintptr(access), uintptr(inherit), uintptr(processID))
	if h == 0 {
		return handle.Handle(0), os.NewSyscallError("OpenProcess", err)
	}
	return handle.Handle(h), nil
}

// QueryFullImageName retrieves the full name of the executable image for the specified process.
func QueryFullImageName(handle handle.Handle) (string, error) {
	var size uint32 = syscall.MAX_PATH
	name := make([]uint16, size)

	errno, _, err := queryFullProcessImageName.Call(uintptr(handle), uintptr(0), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)))
	if winerrno.Errno(errno) != winerrno.Success {
		return syscall.UTF16ToString(name), nil
	}
	return "", os.NewSyscallError("QueryFullProcessImageName", err)
}

// QueryInfo retrieves a variety of process's information depending on the info class passed to this function.
func QueryInfo(handle handle.Handle, infoClass InfoClassFlags, buf []byte) (uint32, error) {
	var size uint32
	if ntQueryInformationProcess != nil {
		errno, _, _ := ntQueryInformationProcess.Call(uintptr(handle), uintptr(infoClass), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&size)))
		if winerrno.Errno(errno) != winerrno.Success {
			if errno == winerrno.StatusInfoLengthMismatch || errno == winerrno.StatusBufferTooSmall {
				return size, errors.ErrNeedsReallocateBuffer
			}
			return size, fmt.Errorf("NtQueryInformationProcess failed with status code 0x%X", errno)
		}
		return size, nil
	}
	return size, nil
}

// ReadMemory reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
func ReadMemory(handle handle.Handle, addr unsafe.Pointer, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	errno, _, err := readProcessMemory.Call(uintptr(handle), uintptr(addr), uintptr(unsafe.Pointer(&buf[0])), size, uintptr(0))
	if winerrno.Errno(errno) != winerrno.Success {
		return buf, nil
	}
	return nil, os.NewSyscallError("ReadProcessMemory", err)
}

func ReadMemoryUnicode(handle handle.Handle, addr unsafe.Pointer, size uintptr) ([]uint16, error) {
	buf := make([]uint16, size)
	errno, _, err := readProcessMemory.Call(uintptr(handle), uintptr(addr), uintptr(unsafe.Pointer(&buf[0])), size, uintptr(0))
	if winerrno.Errno(errno) != winerrno.Success {
		return buf, nil
	}
	return nil, os.NewSyscallError("ReadProcessMemory", err)
}

// GetParentPID returns the identifier of the parent process from the process's basic information structure.
func GetParentPID(handle handle.Handle) uint32 {
	buf := make([]byte, unsafe.Sizeof(BasicInformation{}))
	_, err := QueryInfo(handle, BasicInformationClass, buf)
	if err != nil {
		return uint32(0)
	}
	info := (*BasicInformation)(unsafe.Pointer(&buf[0]))
	return uint32(info.InheritedFromUniqueProcessID)
}

// GetStartTime returns process's timing statistics.
func GetStartTime(handle handle.Handle) (time.Time, error) {
	var (
		ct syscall.Filetime
		xt syscall.Filetime
		kt syscall.Filetime
		ut syscall.Filetime
	)
	errno, _, err := getProcessTimes.Call(uintptr(handle), uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&xt)), uintptr(unsafe.Pointer(&kt)), uintptr(unsafe.Pointer(&ut)))
	if winerrno.Errno(errno) != winerrno.Success {
		return time.Unix(0, ct.Nanoseconds()), nil
	}
	return time.Now(), os.NewSyscallError("GetProcessTime", err)
}

// GetPIDFromThread returns the pid to which the specified thread belongs.
func GetPIDFromThread(handle handle.Handle) (uint32, error) {
	pid, _, err := getProcessIdOfThread.Call(uintptr(handle))
	if pid == 0 {
		return uint32(0), os.NewSyscallError("GetProcessIdOfThread", err)
	}
	return uint32(pid), nil
}

// IsAlive checks if the process identified by the specified handle is still in running state.
func IsAlive(handle handle.Handle) bool {
	var exitCode uint32
	errno, _, _ := getExitCodeProcess.Call(uintptr(handle), uintptr(unsafe.Pointer(&exitCode)))
	if winerrno.Errno(errno) == winerrno.Success {
		return false
	}
	return exitCode == procStatusStillActive
}
