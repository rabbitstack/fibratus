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
	"github.com/rabbitstack/fibratus/pkg/errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go etw.go

//sys startTrace(handle *TraceHandle, name string, props *EventTraceProperties) (err error) [failretval!=0] = advapi32.StartTraceW
//sys controlTrace(handle TraceHandle, name string, props *EventTraceProperties, operation TraceOperation) (err error) [failretval!=0] = advapi32.ControlTraceW
//sys closeTrace(handle TraceHandle) (err error) = advapi32.CloseTrace
//sys openTrace(logfile *EventTraceLogfile) (handle TraceHandle) = advapi32.OpenTraceW
//sys processTrace(handle *TraceHandle, count uint32, start *windows.Filetime, end *windows.Filetime) (err error) [failretval!=0] = advapi32.ProcessTrace
//sys traceSetInformation(handle TraceHandle, infoClass uint8, info uintptr, length uint32) (err error) [failretval!=0] = advapi32.TraceSetInformation
//sys traceQueryInformation(handle TraceHandle, infoClass uint8, info uintptr, length uint32, size *uint32) (err error) [failretval!=0] = advapi32.TraceQueryInformation
//sys enableTraceEx2(handle TraceHandle, providerID *windows.GUID, controlCode uint32, level uint8, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters *EnableTraceParameters) (err error) [failretval!=0] = advapi32.EnableTraceEx2

// EnableTraceParametersVersion determines the version of the EnableTraceParameters structure.
const EnableTraceParametersVersion = 2

// EnableTraceParameters contains information used to enable a provider via EnableTraceEx2.
type EnableTraceParameters struct {
	// Version represents the version of this struct. Should be set to EnableTraceParametersVersion.
	Version uint32
	// EnableProperty represents optional settings that ETW can include
	// when writing the event. Some settings write extra data to the extended
	// data item section of each event. Other settings control which events
	// will be included in the trace.
	EnableProperty uint32
	// ControlFlags is a reserved field and should be set to 0.
	ControlFlags uint32
	// SourceID denotes a GUID that uniquely identifies the caller that
	// is enabling or disabling the provider.
	SourceID windows.GUID
	// EnableFilterDesc is a  pointer to an array of event filter descriptor structures
	// that points to the filter data. The number of elements in the array is specified
	// in the FilterDescCount member.
	EnableFilterDesc uintptr
	// FilterDescCount is the number of elements (filters) in the event filter descriptor
	// array.
	FilterDescCount uint32
}

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
func (trace TraceHandle) IsValid() bool { return trace != 0 && trace != 0xffffffffffffffff }

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
		return TraceHandle(0), errors.ErrTraceAccessDenied
	case windows.ERROR_DISK_FULL:
		return TraceHandle(0), errors.ErrTraceDiskFull
	case windows.ERROR_ALREADY_EXISTS:
		return TraceHandle(0), errors.ErrTraceAlreadyRunning
	case windows.ERROR_INVALID_PARAMETER:
		return TraceHandle(0), errors.ErrTraceInvalidParameter
	case windows.ERROR_BAD_LENGTH:
		return TraceHandle(0), errors.ErrTraceBadLength
	case windows.ERROR_NO_SYSTEM_RESOURCES:
		return TraceHandle(0), errors.ErrTraceNoSysResources
	default:
		return TraceHandle(0), os.NewSyscallError("StartTrace", err)
	}
}

// ControlTrace performs various operation on the specified event tracing session, such as updating, flushing or stopping
// the session.
func ControlTrace(handle TraceHandle, name string, guid windows.GUID, operation TraceOperation) error {
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
func StopTrace(name string, guid windows.GUID) error {
	return ControlTrace(TraceHandle(0), name, guid, Stop)
}

// FlushTrace flushes the buffers of the provided trace.
func FlushTrace(name string, guid windows.GUID) error {
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
		return errors.ErrSessionNotRunning
	case windows.ERROR_NOACCESS:
		return errors.ErrEventCallbackException
	case windows.ERROR_CANCELLED:
		return errors.ErrTraceCancelled
	default:
		return os.NewSyscallError("ProcessTrace", err)
	}
}

// SetTraceSystemFlags enables or disables event tracing session system flags.
func SetTraceSystemFlags(handle TraceHandle, flags []EventTraceFlags) error {
	err := traceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, uintptr(unsafe.Pointer(&flags[0])), uint32(4*len(flags)))
	if err != nil {
		return os.NewSyscallError("TraceSetInformation", err)
	}
	return nil
}

// GetTraceSystemFlags returns enabled event tracing session system flags.
func GetTraceSystemFlags(handle TraceHandle) ([]EventTraceFlags, error) {
	flags := make([]EventTraceFlags, 8)
	err := traceQueryInformation(handle, TraceSystemTraceEnableFlagsInfo, uintptr(unsafe.Pointer(&flags[0])), uint32(4*len(flags)), nil)
	if err != nil {
		return nil, os.NewSyscallError("TraceQueryInformation", err)
	}
	return flags, nil
}

// EventEnablePropertyStacktrace adds a call stack trace to the extended data of events.
// If the stack is longer than the maximum number of frames (192), the frames will be cut
// from the bottom of the stack.
const EventEnablePropertyStacktrace = 0x00000004

const (
	// TraceLevelInformation is the value that indicates the maximum
	// level of events that the provider is susceptible to write.
	TraceLevelInformation = 4
	// ControlCodeEnableProvider updates the session configuration so
	// that the session receives the requested events from the provider.
	ControlCodeEnableProvider = 1
	// ControlCodeCaptureState requests that the provider log its state
	// information, such as rundown events
	ControlCodeCaptureState = 2
)

// EnableTrace influences the behaviour of the specified event trace provider.
func EnableTrace(guid windows.GUID, handle TraceHandle, keywords uint64) error {
	err := enableTraceEx2(handle, &guid, ControlCodeEnableProvider, TraceLevelInformation, keywords, 0, 0, nil)
	if err != nil {
		return os.NewSyscallError("EnableTraceEx2", err)
	}
	return nil
}

// CaptureProviderState requests that the provider log its state information.
func CaptureProviderState(guid windows.GUID, handle TraceHandle) error {
	err := enableTraceEx2(handle, &guid, ControlCodeCaptureState, 0, 0, 0, 0, nil)
	if err != nil {
		return os.NewSyscallError("EnableTraceEx2", err)
	}
	return nil
}

// EnableTraceOpts describes which properties are enabled in the event extended section.
type EnableTraceOpts struct {
	// WithStacktrace indicates call stack trace is added to the extended data of events.
	WithStacktrace bool
}

// EnableTraceWithOpts influences the behaviour of the specified event trace provider
// by providing extra options to configure how events are writing to the session buffer.
func EnableTraceWithOpts(guid windows.GUID, handle TraceHandle, keywords uint64, opts EnableTraceOpts) error {
	params := &EnableTraceParameters{
		Version:  EnableTraceParametersVersion,
		SourceID: guid,
	}
	if opts.WithStacktrace {
		params.EnableProperty = EventEnablePropertyStacktrace
	}
	err := enableTraceEx2(handle, &guid, ControlCodeEnableProvider, TraceLevelInformation, keywords, 0, 0, params)
	if err != nil {
		return os.NewSyscallError("EnableTraceEx2", err)
	}
	return nil
}

// EnableStackTracing enables stack tracing for the provided events.
func EnableStackTracing(handle TraceHandle, eventIDs []ClassicEventID) error {
	err := traceSetInformation(handle, TraceStackTracingInfo, uintptr(unsafe.Pointer(&eventIDs[0])), uint32(unsafe.Sizeof(ClassicEventID{})*uintptr(len(eventIDs))))
	if err != nil {
		return os.NewSyscallError("TraceSetInformation", err)
	}
	return nil
}
