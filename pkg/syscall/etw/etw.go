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

package etw

import (
	"os"
	"syscall"
	"unsafe"

	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	startTrace          = advapi32.NewProc("StartTraceW")
	controlTrace        = advapi32.NewProc("ControlTraceW")
	closeTrace          = advapi32.NewProc("CloseTrace")
	openTrace           = advapi32.NewProc("OpenTraceW")
	processTrace        = advapi32.NewProc("ProcessTrace")
	traceSetInformation = advapi32.NewProc("TraceSetInformation")
	enableTrace         = advapi32.NewProc("EnableTraceEx")
)

// TraceOperation is the type alias for the trace operation.
type TraceOperation uint32

const (
	// Query represents the query trace operation.
	Query TraceOperation = 0
	// Stop represents the stop trace operation.
	Stop TraceOperation = 1
	// Update represents the update trace operation.
	Update TraceOperation = 2
	// Flush represents the flush trace operation.
	Flush TraceOperation = 3
)

// TraceHandle is an alias for trace handle type
type TraceHandle uintptr

// IsValid determines if the session handle is valid
func (handle TraceHandle) IsValid() bool { return handle != 0 }

// StartTrace registers and starts an event tracing session for the specified provider. The trace assumes there will be a real-time
// event consumer responsible for collecting and processing events. If the function succeeds, it returns the handle to the tracing
// session.
func StartTrace(name string, props *EventTraceProperties) (TraceHandle, error) {
	var handle TraceHandle
	errno, _, err := startTrace.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(utf16.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(props)),
	)
	switch winerrno.Errno(errno) {
	case winerrno.Success:
		return handle, nil
	case winerrno.AccessDenied:
		return TraceHandle(0), kerrors.ErrTraceAccessDenied
	case winerrno.DiskFull:
		return TraceHandle(0), kerrors.ErrTraceDiskFull
	case winerrno.AlreadyExists:
		return TraceHandle(0), kerrors.ErrTraceAlreadyRunning
	case winerrno.InvalidParameter:
		return TraceHandle(0), kerrors.ErrTraceInvalidParameter
	case winerrno.BadLength:
		return TraceHandle(0), kerrors.ErrTraceBadLength
	case winerrno.NoSysResources:
		return TraceHandle(0), kerrors.ErrTraceNoSysResources
	default:
		return TraceHandle(0), os.NewSyscallError("StartTrace", err)
	}
}

// ControlTrace performs various operation on the specified event tracing session, such as updating, flushing or stopping
// the session.
func ControlTrace(handle TraceHandle, name string, props *EventTraceProperties, operation TraceOperation) error {
	errno, _, err := controlTrace.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(utf16.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(props)),
		uintptr(operation),
	)
	switch winerrno.Errno(errno) {
	case winerrno.Success:
		return nil
	case winerrno.WMIInstanceNotFound:
		return kerrors.ErrKsessionNotRunning
	default:
		return os.NewSyscallError("ControlTrace", err)
	}
}

// CloseTrace closes a trace. If you call this function before ProcessTrace returns, the CloseTrace function
// returns ErrorCtxClosePending. The ErrorCtxClosePending code indicates that the CloseTrace function call
// was successful; the ProcessTrace function will stop processing events after it processes all events in its buffers.
func CloseTrace(handle TraceHandle) error {
	errno, _, err := closeTrace.Call(uintptr(handle))
	if winerrno.Errno(errno) != winerrno.Success && winerrno.Errno(errno) != winerrno.CtxClosePending {
		return os.NewSyscallError("CloseTrace", err)
	}
	return nil
}

// OpenTrace opens a real-time trace session or log file for consuming.
func OpenTrace(ktrace EventTraceLogfile) TraceHandle {
	handle, _, _ := openTrace.Call(uintptr(unsafe.Pointer(&ktrace)))
	return TraceHandle(handle)
}

// ProcessTrace function delivers events from one or more event tracing sessions to the consumer. Function sorts the events
// chronologically and delivers all events generated between StartTime and EndTime. The ProcessTrace function blocks the
// thread until it delivers all events, the BufferCallback function returns false, or you call CloseTrace.
func ProcessTrace(handle TraceHandle) error {
	errno, _, err := processTrace.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
	switch winerrno.Errno(errno) {
	case winerrno.Success:
		return nil
	case winerrno.WMIInstanceNotFound:
		return kerrors.ErrKsessionNotRunning
	case winerrno.NoAccess:
		return kerrors.ErrEventCallbackException
	case winerrno.Cancelled:
		return kerrors.ErrTraceCancelled
	default:
		return os.NewSyscallError("ProcessTrace", err)
	}
}

// SetTraceInformation enables or disables event tracing session settings for the specified information class.
func SetTraceInformation(handle TraceHandle, infoClass uint8, traceFlags []EventTraceFlags) error {
	errno, _, err := traceSetInformation.Call(uintptr(handle), uintptr(infoClass), uintptr(unsafe.Pointer(&traceFlags[0])), unsafe.Sizeof(traceFlags))
	if winerrno.Errno(errno) == winerrno.Success {
		return nil
	}
	return os.NewSyscallError("TraceSetInformation", err)
}

// EnableTrace influences the behaviour of the specified event trace provider.
func EnableTrace(guid syscall.GUID, handle TraceHandle, keyword uint32) error {
	errno, _, err := enableTrace.Call(uintptr(unsafe.Pointer(&guid)), 0, uintptr(handle), 1, 0, uintptr(keyword), 0, 0, 0)
	if winerrno.Errno(errno) == winerrno.Success {
		return nil
	}
	return os.NewSyscallError("EnableTraceEx", err)
}
