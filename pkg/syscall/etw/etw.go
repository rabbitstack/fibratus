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

package etw

import (
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"unsafe"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go etw.go

//sys startTrace(handle *TraceHandle, name string, props *EventTraceProperties) (err error) [failretval!=0] = advapi32.StartTraceW
//sys controlTrace(handle TraceHandle, name string, props *EventTraceProperties, operation TraceOperation) (err error) [failretval!=0] = advapi32.ControlTraceW
//sys closeTrace(handle TraceHandle) (err error) [failretval!=0] = advapi32.CloseTrace
//sys openTrace(logfile *EventTraceLogfile) (handle TraceHandle) = advapi32.OpenTraceW
//sys processTrace(handle *TraceHandle, count uint32, start *windows.Filetime, end *windows.Filetime) (err error) [failretval!=0] = advapi32.ProcessTrace
//sys traceSetInformation(handle TraceHandle, infoClass uint8, info uintptr, length uint32) (err error) [failretval!=0] = advapi32.TraceSetInformation
//sys enableTraceEx(providerID *syscall.GUID, sourceID *syscall.GUID, handle TraceHandle, isEnabled uint32, level uint8, matchAnyKeyword uint64, matchAllKeyword uint64, enableProperty uint32, enableFilterDesc uintptr) (err error) [failretval!=0] = advapi32.EnableTraceEx

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

// IsValid determines if the trace handle is valid
func (handle TraceHandle) IsValid() bool { return handle != 0 && handle != 0xffffffffffffffff }

// StartTrace registers and starts an event tracing session for the specified provider. The trace assumes there will
// be a real-time event consumer responsible for collecting and processing events. If the function succeeds, it returns
// the handle to the tracing session.
func StartTrace(name string, props EventTraceProperties) (TraceHandle, error) {
	var handle TraceHandle
	err := startTrace(&handle, name, &props)
	if err == nil {
		return handle, nil
	}
	switch err.(windows.Errno) {
	case windows.ERROR_ACCESS_DENIED:
		return TraceHandle(0), kerrors.ErrTraceAccessDenied
	case windows.ERROR_DISK_FULL:
		return TraceHandle(0), kerrors.ErrTraceDiskFull
	case windows.ERROR_ALREADY_EXISTS:
		return TraceHandle(0), kerrors.ErrTraceAlreadyRunning
	case windows.ERROR_INVALID_PARAMETER:
		return TraceHandle(0), kerrors.ErrTraceInvalidParameter
	case windows.ERROR_BAD_LENGTH:
		return TraceHandle(0), kerrors.ErrTraceBadLength
	case windows.ERROR_NO_SYSTEM_RESOURCES:
		return TraceHandle(0), kerrors.ErrTraceNoSysResources
	default:
		return TraceHandle(0), os.NewSyscallError("StartTrace", err)
	}
}

// ControlTrace performs various operation on the specified event tracing session, such as updating, flushing or stopping
// the session.
func ControlTrace(handle TraceHandle, name string, guid syscall.GUID, operation TraceOperation) error {
	props := &EventTraceProperties{
		Wnode: WnodeHeader{
			BufferSize: uint32(unsafe.Sizeof(EventTraceProperties{})) + uint32(2*len(name)),
			GUID:       guid,
		},
	}
	err := controlTrace(handle, name, props, operation)
	if err != nil && err != windows.ERROR_MORE_DATA {
		return os.NewSyscallError("ControlTrace", err)
	}
	return nil
}

// StopTrace stops the provided trace.
func StopTrace(name string, guid syscall.GUID) error {
	return ControlTrace(TraceHandle(0), name, guid, Stop)
}

// FlushTrace flushes the buffers of the provided trace.
func FlushTrace(name string, guid syscall.GUID) error {
	return ControlTrace(TraceHandle(0), name, guid, Flush)
}

// CloseTrace closes a trace. If you call this function before ProcessTrace returns, the CloseTrace function
// returns ErrorCtxClosePending. The ErrorCtxClosePending code indicates that the CloseTrace function call
// was successful; the ProcessTrace function will stop processing events after it processes all events in its buffers.
func CloseTrace(handle TraceHandle) error {
	err := closeTrace(handle)
	if err == nil {
		return nil
	}
	errno := err.(windows.Errno)
	if errno != windows.ERROR_SUCCESS && errno != windows.ERROR_CTX_CLOSE_PENDING {
		return os.NewSyscallError("CloseTrace", err)
	}
	return nil
}

// OpenTrace opens a real-time trace session or log file for consuming.
func OpenTrace(logfile EventTraceLogfile) TraceHandle {
	return openTrace(&logfile)
}

// ProcessTrace function delivers events from one or more event tracing sessions to the consumer. Function sorts the events
// chronologically and delivers all events generated between StartTime and EndTime. The ProcessTrace function blocks the
// thread until it delivers all events, the BufferCallback function returns false, or you call CloseTrace.
func ProcessTrace(handle TraceHandle) error {
	err := processTrace(&handle, 1, nil, nil)
	if err == nil {
		return nil
	}
	switch err.(windows.Errno) {
	case windows.ERROR_WMI_INSTANCE_NOT_FOUND:
		return kerrors.ErrKsessionNotRunning
	case windows.ERROR_NOACCESS:
		return kerrors.ErrEventCallbackException
	case windows.ERROR_CANCELLED:
		return kerrors.ErrTraceCancelled
	default:
		return os.NewSyscallError("ProcessTrace", err)
	}
}

// SetTraceSystemFlags enables or disables event tracing session system flags.
func SetTraceSystemFlags(handle TraceHandle, traceFlags []EventTraceFlags) error {
	err := traceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, uintptr(unsafe.Pointer(&traceFlags[0])), uint32(4*len(traceFlags)))
	if err != nil {
		return os.NewSyscallError("TraceSetInformation", err)
	}
	return nil
}

// EnableTrace influences the behaviour of the specified event trace provider.
func EnableTrace(guid syscall.GUID, handle TraceHandle, keyword uint64) error {
	err := enableTraceEx(&guid, nil, handle, 1, 0, keyword, 0, 0, 0)
	if err != nil {
		return os.NewSyscallError("EnableTraceEx", err)
	}
	return nil
}
