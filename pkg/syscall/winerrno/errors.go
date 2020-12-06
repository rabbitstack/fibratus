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

package winerrno

// Errno is the type alias for error codes returned by API functions
type Errno uintptr

const (
	// InvalidProcessTraceHandle designates an invalid trace handle reference
	InvalidProcessTraceHandle uint64 = 0xffffffffffffffff
	// InvalidPID indicates invalid process identifier value
	InvalidPID uint32 = 0xffffffff
	// StatusInfoLengthMismatch indicates an issue with the parameter length
	StatusInfoLengthMismatch = 0xC0000004
	// StatusBufferTooSmall indicates that the passed memory buffer doesn't have enough space to satisfy the call
	StatusBufferTooSmall = 0xC0000023
	// StatusBufferOverflow indicates that the data was too small to fit in the buffer
	StatusBufferOverflow = 0x80000005
	// Success determines successful return code
	Success Errno = 0x0
	// InvalidParameter defines that the parameter is incorrect
	InvalidParameter Errno = 0x57
	// AlreadyExists cannot create a file when that file already exists
	AlreadyExists Errno = 0xb7
	// DiskFull defines there is not enough space on the disk
	DiskFull Errno = 0x70
	// AccessDenied defines that the access is denied because of insufficient privileges
	AccessDenied Errno = 0x5
	// NoSysResources is thrown when insufficient system resources exist to complete the requested service
	NoSysResources Errno = 0x5aa
	// BadLength is given when the process issued a command but the command length is incorrect
	BadLength Errno = 0x18
	// WMIInstanceNotFound is thrown when he instance name passed was not recognized as valid by a WMI data provider
	WMIInstanceNotFound Errno = 0x1069
	// Cancelled determines the operation was canceled by the user
	Cancelled Errno = 0x4c7
	// NoAccess denotes invalid access to memory location
	NoAccess Errno = 0x3e6
	// InsufficientBuffer determines that the data area passed to a system call is too small
	InsufficientBuffer Errno = 0x7a
	// NotFound denotes that the element is not found
	NotFound Errno = 0x490
	// CtxClosePending indicates that function will stop after it has processed all real-time events in
	// its buffers (it will not receive any new events)
	CtxClosePending Errno = 0x1B5F
)

// IsNotFound returns true is the underlying error is NotFound.
func (e Errno) IsNotFound() bool {
	return e == NotFound
}
