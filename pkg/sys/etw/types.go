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
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// EventTraceFlags is the type alias for kernel trace events
type EventTraceFlags uint32

// KernelTraceControlGUID is the GUID for the kernel system logger
var KernelTraceControlGUID = windows.GUID{Data1: 0x9e814aad, Data2: 0x3204, Data3: 0x11d2, Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}}

// KernelAuditAPICallsGUID represents the GUID for the kernel audit API provider
var KernelAuditAPICallsGUID = windows.GUID{Data1: 0xe02a841c, Data2: 0x75a3, Data3: 0x4fa7, Data4: [8]byte{0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}}

// DNSClientGUID represents the GUID for the Windows DNS Client provider
var DNSClientGUID = windows.GUID{Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9, Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}}

// ThreadpoolGUID represents the GUID for the thread pool provider
var ThreadpoolGUID = windows.GUID{Data1: 0xc861d0e2, Data2: 0xa2c1, Data3: 0x4d36, Data4: [8]byte{0x9f, 0x9c, 0x97, 0x0b, 0xab, 0x94, 0x3a, 0x12}}

// WindowsKernelProcessGUID represents the GUID for the Microsoft Windows Kernel Process provider
var WindowsKernelProcessGUID = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b, Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}

const (
	// TraceStackTracingInfo controls call stack tracing for kernel events
	TraceStackTracingInfo = uint8(3)
	// TraceSystemTraceEnableFlagsInfo controls system logger event flags
	TraceSystemTraceEnableFlagsInfo = uint8(4)
)

// ProcessKeyword enables process events for Microsoft Windows Kernel Process provider
const ProcessKeyword = 0x10

// ImageKeyword enables images events for Microsoft Windows Kernel Process provider
const ImageKeyword = 0x40

const (
	// EventHeaderExtTypeStackTrace64 indicates that the extended data contains the call stack if the event is captured on a 64-bit host
	EventHeaderExtTypeStackTrace64 uint16 = 0x0006
)

const (
	// KernelLoggerSession represents the default session name for NT kernel logger
	KernelLoggerSession = "NT Kernel Logger"
	// SecurityTelemetrySession represents the session name for all security telemetry
	SecurityTelemetrySession = "Security Telemetry Logger"

	// WnodeTraceFlagGUID indicates that the structure contains event tracing information
	WnodeTraceFlagGUID = 0x00020000
	// ProcessTraceModeRealtime denotes that there will be a real-time consumers for events forwarded from the providers
	ProcessTraceModeRealtime = 0x00000100
	// ProcessTraceModeEventRecord is the mode that enables the "event record" format for kernel events
	ProcessTraceModeEventRecord = 0x10000000
)

const (
	// ALPC flag activates ALPC events
	ALPC EventTraceFlags = 0x00100000
	// Cswitch flag enables context switch events
	Cswitch EventTraceFlags = 0x00000010
	// DbgPrint flag enables stack walk information
	DbgPrint EventTraceFlags = 0x00040000
	// DiskFileIO flag enables file system events
	DiskFileIO EventTraceFlags = 0x00000200
	// DiskIO flag enables disk I/O events
	DiskIO EventTraceFlags = 0x00000100
	// DiskIOInit flag enables start/end disk I/O events
	DiskIOInit EventTraceFlags = 0x00000400
	// Dispatcher flag activates dispatcher events
	Dispatcher EventTraceFlags = 0x00000800
	// DPC flag enables Deferred Procedure Call events
	DPC EventTraceFlags = 0x00000020
	// Driver flag enables driver events
	Driver EventTraceFlags = 0x00800000
	// FileIO enables file I/O events.
	FileIO EventTraceFlags = 0x02000000
	// FileIOInit flag enables file start/end events.
	FileIOInit EventTraceFlags = 0x04000000
	// ImageLoad flag enables image events.
	ImageLoad EventTraceFlags = 0x00000004
	// Handle flag enables handle events.
	Handle EventTraceFlags = 0x80000040
	// IRQ flag enables IRQ events.
	IRQ EventTraceFlags = 0x00000040
	// Job flag enables job events.
	Job EventTraceFlags = 0x00080000
	// NetTCPIP flag enables network events.
	NetTCPIP EventTraceFlags = 0x00010000
	// Process flag enables process events.
	Process EventTraceFlags = 0x00000001
	// Registry flag enable registry events.
	Registry EventTraceFlags = 0x00020000
	// Syscall flag enables syscall enter/exit events.
	Syscall EventTraceFlags = 0x00000080
	// Thread flag enables thread events.
	Thread EventTraceFlags = 0x00000002
	// VaMap enables map and unmap file events.
	VaMap EventTraceFlags = 0x00008000
	// VirtualAlloc enables virtual memory allocation and free events.
	VirtualAlloc EventTraceFlags = 0x00004000
)

// String returns the string representation of enabled event trace flags.
func (f EventTraceFlags) String() string {
	flags := make([]string, 0)
	if f&ALPC == ALPC {
		flags = append(flags, "ALPC")
	}
	if f&Cswitch == Cswitch {
		flags = append(flags, "Cswitch")
	}
	if f&DiskFileIO == DiskFileIO {
		flags = append(flags, "DiskFileIO")
	}
	if f&DiskIO == DiskIO {
		flags = append(flags, "DiskIO")
	}
	if f&FileIO == FileIO {
		flags = append(flags, "FileIO")
	}
	if f&ImageLoad == ImageLoad {
		flags = append(flags, "DLL")
	}
	if f&Handle == Handle {
		flags = append(flags, "Handle")
	}
	if f&NetTCPIP == NetTCPIP {
		flags = append(flags, "TCPIP")
	}
	if f&Process == Process {
		flags = append(flags, "Process")
	}
	if f&Registry == Registry {
		flags = append(flags, "Registry")
	}
	if f&Thread == Thread {
		flags = append(flags, "Thread")
	}
	if f&VaMap == VaMap {
		flags = append(flags, "VaMap")
	}
	if f&VirtualAlloc == VirtualAlloc {
		flags = append(flags, "VirtualAlloc")
	}
	return strings.Join(flags, ", ")
}

// WnodeHeader is a member of `EventTraceProperties` structure. The majority of the fields in this structure are not relevant to us.
type WnodeHeader struct {
	// BufferSize is the total size of memory allocated, in bytes, for the event tracing session properties.
	BufferSize uint32
	// ProviderID is reserved for internal use.
	ProviderID uint32
	// HostricalContext is union field with the following C representation:
	// union {
	//	ULONG64 HistoricalContext;
	//	struct {
	//	  ULONG Version;
	//	  ULONG Linkage;
	//	};
	// };
	// On output, HistoricalContext stores the handle to the event tracing session. Version and Linkage fields are reserved for internal use.
	HistoricalContext [8]byte
	// KernelHandle is union with the following C representation:
	// union {
	//	HANDLE        KernelHandle;
	//	LARGE_INTEGER TimeStamp;
	//  };
	// `KernelHandle` is reserved for internal use. `TimeStamp` designates the instant at which the information of this
	// structure was updated.
	KernelHandle [8]byte
	// GUID that defines the session. For NT Kernel Logger session we have to set this member to `SystemTraceControlGuid`.
	GUID windows.GUID
	// ClientContext represents clock resolution to use when logging the time stamp for each event. The default is Query performance counter (QPC).
	ClientContext uint32
	// Flags must contain `WnodeFlagTracedGUID` to indicate that the structure contains event tracing information.
	Flags uint32
}

// EventTraceProperties contains information about an event tracing session. Each time a new session is created, or an existing session
// is about to be modified, this structure is used to describe session properties.
type EventTraceProperties struct {
	// Wnode structure requires `BufferSize`, `Flags` and `GUID` members to be initialized.
	Wnode WnodeHeader
	// BufferSize represents the amount of memory allocated for each event tracing session buffer, in kilobytes.
	// The maximum buffer size is 1 MB. ETW uses the size of physical memory to calculate this value.
	// If an application expects a relatively low event rate, the buffer size should be set to the memory page size.
	// To get the page memory size, you can invoke GetSystemInfo() function.
	// If the event rate is expected to be relatively high, the application should specify a larger buffer size,
	// and should increase the maximum number of buffers.
	//
	// The buffer size affects the rate at which buffers fill and must be flushed. Although a small buffer size requires
	// less memory, it increases the rate at which buffers must be flushed.
	BufferSize uint32
	// MinimumBuffers specifies the minimum number of buffers allocated for the event tracing session's buffer pool.
	// The minimum number of buffers that you can specify is two buffers per processor. For example, on a single processor machine,
	// the minimum number of buffers is two.
	MinimumBuffers uint32
	// MaximumBuffers is the maximum number of buffers allocated for the event tracing session's buffer pool. Typically, this value is
	// the minimum number of buffers plus twenty. ETW uses the buffer size and the size of physical memory to calculate this value.
	MaximumBuffers uint32
	// MaximumFileSize is the maximum size of the file used to log events, in megabytes.
	MaximumFileSize uint32
	// LogFileMode determines the logging modes for the event tracing session. You use this member to specify that you want events written to a
	// log file, a real-time consumer, or both. In real-time logging mode, if no consumers are available, events will be written
	// to disk, and when consumers begin processing real-time events, the events in the playback file are consumed first.
	LogFileMode uint32
	// FlushTimer specifies how often, in seconds, the trace buffers are forcibly flushed. The minimum flush time is 1 second.
	// This forced flush is in addition to the automatic flush that occurs whenever a buffer is full and when the trace session
	// stops. If zero, ETW flushes buffers as soon as they become full. If nonzero, ETW flushes all buffers that contain events
	// based on the timer value. Typically, you want to flush buffers only when they become full. Forcing the buffers to flush
	// (either by setting this member to a nonzero value or by calling `FlushTrace`) can increase the file size of the log file
	// with unfilled buffer space.
	//
	// If the consumer is consuming events in real time, you may want to set this member to a nonzero value if the event rate is
	// low to force events to be delivered before the buffer is full.
	// For the case of a realtime logger, a value of zero (the default value) means that the flush time will be set to 1 second.
	// A realtime logger is when LogFileMode is set to `EventTraceRealTimeMode`.
	FlushTimer uint32
	// EnableFlags specifies which kernel events are delivered to the consumer when NT Kernel logger session is started.
	// For example, registry events, process, disk IO and so on.
	EnableFlags EventTraceFlags
	// AgeLimit is not used.
	AgeLimit int32
	// NumberOfBuffers indicates the number of buffers allocated for the event tracing session's buffer pool.
	NumberOfBuffers uint32
	// FreeBuffers indicates the number of buffers that are allocated but unused in the event tracing session's buffer pool.
	FreeBuffers uint32
	// EventsLost counts the number of events that were not recorded.
	EventsLost uint32
	// BuffersWritten counts the number of buffers written.
	BuffersWritten uint32
	// LogBuffersLost determines the number of buffers that could not be written to the log file.
	LogBuffersLost uint32
	// RealTimeBuffersLost represents the number of buffers that could not be delivered in real-time to the consumer.
	RealTimeBuffersLost uint32
	// LoggerThreadID is the thread identifier for the event tracing session.
	LoggerThreadID uintptr
	// LogFileNameOffset is the offset from the start of the structure's allocated memory to beginning of the null-terminated
	// string that contains the log file name.
	LogFileNameOffset uint32
	// LoggerNameOffset is the offset from the start of the structure's allocated memory to beginning of the null-terminated
	// string that contains the session name. The session name is limited to 1024 characters. The session name is case-insensitive
	// and must be unique.
	LoggerNameOffset uint32
}

// EventTraceHeader contains standard event tracing information common to all events.
type EventTraceHeader struct {
	// Size represents the total number of bytes of the event. It includes the size of the header structure,
	// plus the size of any event-specific data appended to the header.
	Size uint16
	// FieldTypeFlags is union field represented as follows:
	//  union {
	//	USHORT FieldTypeFlags;
	//	struct {
	//	  UCHAR HeaderType;
	//	  UCHAR MarkerFlags;
	//	};
	// };
	// All memebers of this union are reserved for internal use.
	FieldTypeFlags [2]byte
	// Versions in union field with the following declaration:
	// union {
	//	ULONG  Version;
	//	struct {
	//	  UCHAR  Type;
	//	  UCHAR  Level;
	//	  USHORT Version;
	//	} Class;
	//  };
	// `Type` field indicates the general purpose type of this event (e.g. data collection end/start, checkpoint, etc.)
	// `Level` designates the severity of the generated event and the `Version` tells the consumer which MOF class to use to
	// decipher the event data.
	Version [4]byte
	// ThreadID identifies the thread that generated this event.
	ThreadID uint32
	// ProcessID identifies the process that generated this event.
	ProcessID uint32
	// Timestamp contains the time that the event occurred.
	Timestamp uint64
	// GUID is union:
	// union {
	//	GUID      Guid;
	//	ULONGLONG GuidPtr;
	// };
	// `Guid` identifies a category of events. `GuidPtr` is the pointer to an event trace class GUID.
	GUID [16]byte
	// ProcessorTime is another union type:
	// union {
	//	struct {
	//		ULONG ClientContext;
	//		ULONG Flags;
	//	  };
	//	  struct {
	//		ULONG KernelTime;
	//		ULONG UserTime;
	//	  };
	//	  ULONG64 ProcessorTime;
	// };
	// `ClientContext` is reserved, while `Flags` must be set to `WnodeFlagTracedGuid`. The rest of the members
	// specify elapsed execution time for kernel and user mode instructions respectively.
	ProcessorTime [8]byte
}

// EventTrace stores event information that is delivered to an event trace consumer.
type EventTrace struct {
	// Header contains standard event tracing metadata.
	Header EventTraceHeader
	// InstanceID represents the instance identifier.
	InstanceID uint32
	// ParentInstanceID represents instance identifier for a parent event.
	ParentInstanceID uint32
	// ParentGUID is the class GUID of the parent event.
	ParentGUID windows.GUID
	// MofData is the pointer to the beginning of the event-specific data for this event.
	MofData uintptr
	// MofLength represents the number of bytes to which `MofData` points.
	MofLength uint32
	// Context is union type:
	// union {
	//	ULONG              ClientContext;
	//	ETW_BUFFER_CONTEXT BufferContext;
	// };
	// `ClientContext` field is reserved. `BufferContext` Provides information about the event such as the session identifier
	// and processor number of the CPU on which the provider process ran.
	Context [2]byte
}

// TraceLogfileHeader contains information about an event tracing session and its events.
type TraceLogfileHeader struct {
	// BufferSize is the size of the event tracing session's buffers in bytes.
	BufferSize uint32
	// Version is the union type that represents version number of the operating system.
	Version [4]byte
	// ProviderVersion is the build number of the operating system.
	ProviderVersion uint32
	// NumberOfProcessors indicates the number of processors on the system.
	NumberOfProcessors uint32
	// EndTime is the time at which the event tracing session stopped. This value is 0 for real time event consumers.
	EndTime uint64
	// TimerResolution is the resolution of the hardware timer, in units of 100 nanoseconds.
	TimerResolution uint32
	// MaximumFileSize is the size of the log file, in megabytes.
	MaximumFileSize uint32
	// LogfileMode represents the current logging mode for the event tracing session.
	LogfileMode uint32
	// BuffersWritten is the total number of buffers written by the event tracing session.
	BuffersWritten uint32
	// GUID is union type with the two first field reserved for internal usage. Other fields indicate
	// the number of events lost and the CPU speed in Mhz.
	GUID [16]byte
	// LoggerName is a reserved field.
	LoggerName *uint16
	// LogfileName is a reserved field.
	LogfileName *uint16
	// TimeZone contains time-zone information for `BootTime`, `EndTime` and `StartTime` fields.
	TimeZone windows.Timezoneinformation
	// BootTime is the time at which the system was started, in 100-nanosecond intervals since midnight, January 1, 1601.
	BootTime uint64
	// PerfFreq is the frequency of the high-resolution performance counter, if one exists.
	PerfFreq uint64
	// StartTime is the time at which the event tracing session started, in 100-nanosecond intervals since midnight, January 1, 1601.
	StartTime uint64
	// ReservedFlags specifies the clock type.
	ReservedFlags uint32
	// BuffersLost is the total number of buffers lost during the event tracing session.
	BuffersLost uint32
}

// EventTraceLogfile specifies how the consumer wants to read events (from a log file or in real-time) and the callbacks
// that will receive the events.When ETW flushes a buffer, this structure contains information about the event tracing
// session and the buffer that ETW flushed.
type EventTraceLogfile struct {
	// LogFileName is the name of the log file used by the event tracing session.
	LogFileName *uint16
	// LoggerName is the name of the event tracing session. Only applicable when consuming events in real time.
	LoggerName *uint16
	// CurrentTime on output, the current time, in 100-nanosecond intervals since midnight, January 1, 1601.
	CurrentTime int64
	// BuffersRead represents the number of buffers processed.
	BuffersRead uint32
	// LogFileMode is union type the dictates the processing mode for events.
	LogFileMode [4]byte
	// CurrentEvents contains the last event processed.
	CurrentEvent EventTrace
	// LogfileHeader represents global information about the tracing session.
	LogfileHeader TraceLogfileHeader
	// BufferCallback is a pointer to the function that receives buffer-related statistics for each buffer ETW flushes.
	// ETW calls this callback after it delivers all the events in the buffer.
	BufferCallback uintptr
	// BufferSize contains the size of each buffer, in bytes.
	BufferSize uint32
	// Filled contains the number of bytes in the buffer that contain valid information.
	Filled uint32
	// EventsLost is an unused field.
	EventsLost uint32
	// EventCallback is the union field that contains pointers to callback functions that ETW calls for each buffer.
	EventCallback [8]byte
	// IsKernelTrace specifies whether the event tracing session is the NT kernel logger.
	IsKernelTrace uint32
	// Context is data that a consumer can specify when calling `OpenTrace` function.
	Context uintptr
}

// NewEventTraceLogfile creates a new event trace logfile structure.
func NewEventTraceLogfile(loggerName string) EventTraceLogfile {
	return EventTraceLogfile{
		LoggerName: windows.StringToUTF16Ptr(loggerName),
	}
}

// SetModes sets the event processing modes.
func (e *EventTraceLogfile) SetModes(modes int) {
	*(*uint32)(unsafe.Pointer(&e.LogFileMode[0])) = uint32(modes)
}

// SetEventCallback sets the event processing callback.
func (e *EventTraceLogfile) SetEventCallback(fn uintptr) {
	*(*uintptr)(unsafe.Pointer(&e.EventCallback[4])) = fn
}

// SetBufferCallback sets the session buffer reporting callback.
func (e *EventTraceLogfile) SetBufferCallback(fn uintptr) {
	e.BufferCallback = fn
}

// EventDescriptor contains metadata that defines the event.
type EventDescriptor struct {
	// ID represents event identifier.
	ID uint16
	// Version indicates a revision to the event definition.
	Version uint8
	// Channel is the audience for the event (e.g. administrator or developer).
	Channel uint8
	// Level is the severity or level of detail included in the event.
	Level uint8
	// Opcode is step in a sequence of operations being performed within the `Task` field. For MOF-defined events,
	// the `Opcode` member contains the event type value.
	Opcode uint8
	// Task represents a larger unit of work within an application or component.
	Task uint16
	// Keyword A bitmask that specifies a logical group of related events. Each bit corresponds to one group. An event may belong to one or more groups.
	// The keyword can contain one or more provider-defined keywords, standard keywords, or both.
	Keyword uint64
}

// EventHeader defines information about the event.
type EventHeader struct {
	// Size represents the size of the event, in bytes.
	Size uint16
	// HeaderType is reserved.
	HeaderType uint16
	// Flags provides information about the event such as the type of session it was logged to and if
	// the event contains extended data.
	Flags uint16
	// EventProperty indicates the source to use for parsing the event data.
	EventProperty uint16
	// ThreadID identifies the thread that generated the event.
	ThreadID uint32
	// ProcessID identifies the process that generated the event.
	ProcessID uint32
	// Timestamps contains the time that the event occurred.
	Timestamp uint64
	// ProviderID is the GUID that uniquely identifies the provider that logged the event.
	ProviderID windows.GUID
	// EventDescriptor defines the information about the event such as the event identifier and severity level.
	EventDescriptor EventDescriptor
	// ProcessorTime is the union type that defines elapsed execution time for kernel-mode and user-mode instructions
	// in CPU units.
	ProcessorTime [8]byte
	// ActivityID is the identifier that relates two events.
	ActivityID windows.GUID
}

// BufferContext provides context information about the event.
type BufferContext struct {
	// ProcessorIndex is union type that contains among other fields the number of the CPU on which
	// the provider process was running.
	ProcessorIndex [2]byte
	// LoggerID identifies of the session that logged the event.
	LoggerID uint16
}

// Linkage is the inner struct for EventHeaderExtendedDataItem.
type Linkage struct {
	Linkage uint16
}

// EventHeaderExtendedDataItem defines the extended data that ETW collects as part of the event data.
type EventHeaderExtendedDataItem struct {
	// Reserved1 is a reserved field.
	Reserved1 uint16
	// ExtType defines the type of extended data.
	ExtType uint16
	// Linkage is a reserved field.
	Linkage Linkage
	// DataSize is the size in bytes, of the extended data
	DataSize uint16
	// DataPtr is the pointer to extended data.
	DataPtr uint64
}

// EventRecord defines the layout of an event that ETW delivers.
type EventRecord struct {
	// Header represents information about the event such as the time stamp for when it was written.
	Header EventHeader
	// BufferContext defines information such as the session that logged the event.
	BufferContext BufferContext
	// ExtendedDataCount is the number of extended data structures in the `ExtendedData` field.
	ExtendedDataCount uint16
	// BufferLen represents the size, in bytes, of the event data buffer
	BufferLen uint16
	// ExtendedData designates extended data items that ETW collects. The extended data includes some items, such as the security
	// identifier (SID) of the user that logged the event.
	ExtendedData *EventHeaderExtendedDataItem
	// Buffer represents raw event data that's parsed via TDH API.
	Buffer uintptr
	// UserContext is a pointer to custom user data passed in `EventTraceLogfile` structure.
	UserContext uintptr
}

// ClassicEventID identifies the event for which the call stack is enabled.
type ClassicEventID struct {
	// GUID identifies the event class
	GUID windows.GUID
	// Type is type that identifies the event within the kernel event class to enable
	Type uint8
	_    [7]uint8 // reserved
}

// NewClassicEventID creates a new instance of classic event identifier.
func NewClassicEventID(guid windows.GUID, typ uint16) ClassicEventID {
	return ClassicEventID{GUID: guid, Type: uint8(typ)}
}

// Version returns the version of the event schema.
func (e *EventRecord) Version() uint8 {
	return e.Header.EventDescriptor.Version
}

// HookID returns either the opcode or the event ID.
func (e *EventRecord) HookID() uint16 {
	if e.Header.EventDescriptor.Opcode > 0 {
		return uint16(e.Header.EventDescriptor.Opcode)
	}
	return e.Header.EventDescriptor.ID
}

// ID is an unsigned integer that uniquely
// identifies the event. Handy for bitmask
// operations.
func (e *EventRecord) ID() uint {
	d1 := e.Header.ProviderID.Data1
	d2 := e.Header.ProviderID.Data2

	id := uint(byte(d1>>24))<<56 |
		uint(byte(d1>>16))<<48 |
		uint(byte(d1>>8))<<40 |
		uint(byte(d1))<<32 |
		uint(byte(d2>>8))<<24 |
		uint(byte(d2))<<16 |
		uint(e.HookID())

	return id
}

// ReadByte reads the byte from the buffer at the specified offset.
func (e *EventRecord) ReadByte(offset uint16) byte {
	if offset > e.BufferLen {
		return 0
	}
	return *(*byte)(unsafe.Pointer(e.Buffer + uintptr(offset)))
}

// ReadBytes reads a contiguous block of bytes from the buffer.
func (e *EventRecord) ReadBytes(offset uint16, count uint16) []byte {
	if offset > e.BufferLen {
		return nil
	}
	return (*[1<<30 - 1]byte)(unsafe.Pointer(e.Buffer + uintptr(offset) + uintptr(count)))[:count:count]
}

// ReadUint16 reads the uint16 value from the buffer at the specified offset.
func (e *EventRecord) ReadUint16(offset uint16) uint16 {
	if offset > e.BufferLen {
		return 0
	}
	return *(*uint16)(unsafe.Pointer(e.Buffer + uintptr(offset)))
}

// ReadUint32 reads the uint32 value from the buffer at the specified offset.
func (e *EventRecord) ReadUint32(offset uint16) uint32 {
	if offset > e.BufferLen {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(e.Buffer + uintptr(offset)))
}

// ReadUint64 reads the uint64 value from the buffer at the specified offset.
func (e *EventRecord) ReadUint64(offset uint16) uint64 {
	if offset > e.BufferLen {
		return 0
	}
	return *(*uint64)(unsafe.Pointer(e.Buffer + uintptr(offset)))
}

// ReadAnsiString reads the ANSI string from the buffer at the specified offset.
// Returns the UTF-8 string and the number of bytes read from the string.
func (e *EventRecord) ReadAnsiString(offset uint16) (string, uint16) {
	if offset > e.BufferLen {
		return "", 0
	}
	b := make([]byte, e.BufferLen)
	var i uint16
	for i < e.BufferLen {
		c := *(*byte)(unsafe.Pointer(e.Buffer + uintptr(offset) + uintptr(i)))
		if c == 0 {
			break // null terminator
		}
		b[i] = c
		i++
	}
	if int(i) > len(b) {
		return string(b[:len(b)-1]), uint16(len(b))
	}
	return string(b[:i]), i + 1
}

// ReadUTF16String reads the UTF-16 string from the buffer at the specified offset.
// Returns the UTF-8 string and the number of bytes read from the string.
func (e *EventRecord) ReadUTF16String(offset uint16) (string, uint16) {
	if offset > e.BufferLen {
		return "", 0
	}

	var length uint16

	if offset > 0 {
		length = e.BufferLen - offset
	} else {
		// we're reading the leading string. First, calculate
		// the length of the null-terminated UTF16 string
		var i uint16
		for i < e.BufferLen {
			c := *(*uint16)(unsafe.Pointer(e.Buffer + uintptr(i)))
			if c == 0 {
				break // null terminator
			}
			length += 2
			i += 2
		}
	}

	s := (*[1<<30 - 1]uint16)(unsafe.Pointer(e.Buffer + uintptr(offset)))[:length:length]
	if offset > 0 {
		return utf16.Decode(s[:len(s)/2-1-2]), uint16(len(s) + 2)
	}

	return utf16.Decode(s[:len(s)/2]), uint16(len(s) + 2)
}

// ReadNTUnicodeString reads the native Unicode string at the given offset.
func (e *EventRecord) ReadNTUnicodeString(offset uint16) (string, uint16) {
	if offset > e.BufferLen {
		return "", offset
	}

	i := offset
	var length uint16
	for i < e.BufferLen {
		c := *(*uint16)(unsafe.Pointer(e.Buffer + uintptr(i)))
		if c == 0 {
			break // null terminator
		}
		length += 2
		i += 2
	}

	if length == 0 {
		return "", offset
	}

	b := (*[1<<30 - 1]byte)(unsafe.Pointer(e.Buffer + uintptr(offset)))[:length:length]

	s := windows.NTUnicodeString{
		Length:        uint16(len(b)),
		MaximumLength: uint16(len(b)),
		Buffer:        (*uint16)(unsafe.Pointer(&b[0])),
	}

	return s.String(), offset + s.Length
}

// ConsumeUTF16String reads the byte slice with UTF16-encoded string
// when the UTF16 string is located at the end of the buffer.
func (e *EventRecord) ConsumeUTF16String(offset uint16) string {
	if offset > e.BufferLen {
		return ""
	}
	s := (*[1<<30 - 1]uint16)(unsafe.Pointer(e.Buffer + uintptr(offset)))[: e.BufferLen-offset : e.BufferLen-offset]
	return utf16.Decode(s[:len(s)/2-1])
}

// ReadSID reads the security identifier from the event buffer.
func (e *EventRecord) ReadSID(offset uint16, isWbemSid bool) ([]byte, uint16) {
	// this is a Security Token which can be null and takes 4 bytes.
	// Otherwise, it is an 8 byte structure (TOKEN_USER) followed by SID,
	// which is variable size depending on the 2nd byte in the SID
	sid := e.ReadUint32(offset)
	if sid == 0 {
		return nil, offset + 4
	}

	var tokenSize uint16
	if isWbemSid {
		tokenSize = 16 // TOKEN_USER size
	}

	authorities := e.ReadByte(offset + (tokenSize + 1))
	end := offset + tokenSize + 8 + 4*uint16(authorities)
	b := make([]byte, end-offset)
	i := offset
	for i < end {
		b[i-offset] = *(*byte)(unsafe.Pointer(e.Buffer + uintptr(i)))
		i++
	}
	return b, end
}

// EventExtendedItemStackTrace64 defines a call stack on a 64-bit machine.
type EventExtendedItemStackTrace64 struct {
	// MatchID represents the unique identifier that you use to match
	// the kernel-mode calls to the user-mode calls; the kernel-mode
	// calls and user-mode calls are captured in separate events if
	// the environment prevents both from being captured in the same event.
	// If the kernel-mode and user-mode calls were captured in the same event,
	// the value is zero.
	MatchID uint64
	// Address is an array of call addresses on the stack.
	Address [1]uint64
}

// HasStackTrace determines if the event has the stack trace extended item.
func (e *EventRecord) HasStackTrace() bool {
	if e.ExtendedDataCount == 0 {
		return false
	}
	data := (*[1 << 23]EventHeaderExtendedDataItem)(unsafe.Pointer(e.ExtendedData))[:e.ExtendedDataCount:e.ExtendedDataCount]
	for _, n := range data {
		if n.ExtType == EventHeaderExtTypeStackTrace64 {
			return true
		}
	}
	return false
}

// Callstack collects the event stack trace for
// events emitted by non-system logger providers.
func (e *EventRecord) Callstack() []va.Address {
	if e.ExtendedDataCount == 0 {
		return nil
	}
	data := (*[1 << 23]EventHeaderExtendedDataItem)(unsafe.Pointer(e.ExtendedData))[:e.ExtendedDataCount:e.ExtendedDataCount]
	for _, n := range data {
		if n.ExtType != EventHeaderExtTypeStackTrace64 {
			continue
		}
		s := (*EventExtendedItemStackTrace64)(unsafe.Pointer(uintptr(n.DataPtr)))
		if s == nil {
			continue
		}
		// number of return addresses
		length := (n.DataSize - 8) / 8
		addrs := make([]va.Address, length)
		addresses := unsafe.Slice(&s.Address[0], length)
		for i, addr := range addresses {
			addrs[i] = va.Address(addr)
		}
		return addrs
	}
	return nil
}
