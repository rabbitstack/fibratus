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

package thread

import (
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	openThread      = kernel32.NewProc("OpenThread")
	createThread    = kernel32.NewProc("CreateThread")
	terminateThread = kernel32.NewProc("TerminateThread")
)

// DesiredAccess defines the type alias for thread's access modifiers
type DesiredAccess uint32

const (
	// QueryLimitedInformation is required to get certain information from the thread objects (e.g. PID to which pertains some thread)
	QueryLimitedInformation DesiredAccess = 0x0800
)

type threadNameInfo struct {
	ThreadName utf16.UnicodeString
}

// Open opens an existing thread object.
func Open(access DesiredAccess, inheritHandle bool, threadID uint32) (handle.Handle, error) {
	var inherit uint8
	if inheritHandle {
		inherit = 1
	} else {
		inherit = 0
	}
	h, _, err := openThread.Call(uintptr(access), uintptr(inherit), uintptr(threadID))
	if h == 0 {
		return handle.Handle(0), os.NewSyscallError("OpenThread", err)
	}
	return handle.Handle(h), nil
}

func Create(ctx unsafe.Pointer, cb uintptr) (handle.Handle, uint32, error) {
	var threadID uint32
	h, _, err := createThread.Call(0, 0, cb, uintptr(ctx), 0, uintptr(unsafe.Pointer(&threadID)))
	if h == 0 {
		return handle.Handle(0), threadID, os.NewSyscallError("CreateThread", err)
	}
	return handle.Handle(h), threadID, nil
}

func Terminate(handle handle.Handle, exitCode uint32) error {
	errno, _, err := terminateThread.Call(uintptr(handle), uintptr(exitCode))
	if errno == 0 {
		return os.NewSyscallError("TerminateThread", err)
	}
	return nil
}
