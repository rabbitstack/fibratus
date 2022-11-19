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

package thread

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
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
	// TerminateThread is required to terminate a thread using `TerminateThread`
	TerminateThread DesiredAccess = 0x0001
	// SuspendResume is required to suspend or resume a thread
	SuspendResume DesiredAccess = 0x0002
	// GetContext is required to read the context of a thread using `GetThreadContext`
	GetContext DesiredAccess = 0x0008
	// SetContext is required to write the context of a thread
	SetContext DesiredAccess = 0x0010
	// SetInformation is required to set certain information in the thread object
	SetInformation DesiredAccess = 0x0020
	// QueryInformation is required to read certain information from the thread object
	QueryInformation DesiredAccess = 0x0040
	// SetThreadToken is required to set the impersonation token for a thread
	SetThreadToken DesiredAccess = 0x0080
	// Impersonate is required to use a thread's security information directly without calling it by using a communication mechanism that provides impersonation services
	Impersonate DesiredAccess = 0x0100
	// DirectImpersonation is required for a server thread that impersonates a client
	DirectImpersonation DesiredAccess = 0x0200
	// SetLimitedInformation is required to set certain information in the thread object
	SetLimitedInformation DesiredAccess = 0x0400
	// QueryLimitedInformation is required to get certain information from the thread objects (e.g. PID to which pertains some thread)
	QueryLimitedInformation DesiredAccess = 0x0800

	// AllAccess grants all possible access rights for a thread object
	AllAccess DesiredAccess = 0x000F0000 | 0x00100000 | 0xFFFF
)

// String returns the human-readable representation of the thread access rights.
func (access DesiredAccess) String() string {
	switch access {
	case TerminateThread:
		return "TERMINATE"
	case SuspendResume:
		return "SUSPEND_RESUME"
	case GetContext:
		return "GET_CONTEXT"
	case SetContext:
		return "SET_CONTEXT"
	case SetInformation:
		return "SET_INFORMATION"
	case QueryInformation:
		return "QUERY_INFORMATION"
	case SetThreadToken:
		return "SET_THREAD_TOKEN"
	case Impersonate:
		return "IMPERSONATE"
	case DirectImpersonation:
		return "DIRECT_IMPERSONATION"
	case SetLimitedInformation:
		return "SET_LIMITED_INFORMATION"
	case QueryLimitedInformation:
		return "QUERY_LIMITED_INFORMATION"
	case AllAccess:
		return "ALL_ACCESS"
	default:
		return "UNKNOWN"
	}
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

// Create creates a thread to execute within the virtual address space of the calling process.
func Create(ctx unsafe.Pointer, cb uintptr) (handle.Handle, uint32, error) {
	var threadID uint32
	h, _, err := createThread.Call(0, 0, cb, uintptr(ctx), 0, uintptr(unsafe.Pointer(&threadID)))
	if h == 0 {
		return handle.Handle(0), threadID, os.NewSyscallError("CreateThread", err)
	}
	return handle.Handle(h), threadID, nil
}

// Terminate terminates the specified thread.
func Terminate(handle handle.Handle, exitCode uint32) error {
	errno, _, err := terminateThread.Call(uintptr(handle), uintptr(exitCode))
	if errno == 0 {
		return os.NewSyscallError("TerminateThread", err)
	}
	return nil
}
