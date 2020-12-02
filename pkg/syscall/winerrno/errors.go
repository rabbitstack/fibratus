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
	InvalidPID               uint32 = 0xffffffff
	StatusInfoLengthMismatch        = 0xC0000004
	StatusBufferTooSmall            = 0xC0000023
	// StatusBufferOverflow indicates that the data was too small to fit in the buffer
	StatusBufferOverflow = 0x80000005
	// Success determines successful return code
	Success             Errno = 0x0
	InvalidParameter    Errno = 0x57
	AlreadyExists       Errno = 0xb7
	DiskFull            Errno = 0x70
	AccessDenied        Errno = 0x5
	NoSysResources      Errno = 0x5aa
	BadLength           Errno = 0x18
	WMIInstanceNotFound Errno = 0x1069
	Cancelled           Errno = 0x4c7
	NoAccess            Errno = 0x3e6
	InsufficientBuffer  Errno = 0x7a
	NotFound            Errno = 0x490
	// CtxClosePending indicates that function will stop after it has processed all real-time events in
	// its buffers (it will not receive any new events)
	CtxClosePending Errno = 0x1B5F
)

func (e Errno) IsNotFound() bool {
	return e == NotFound
}
