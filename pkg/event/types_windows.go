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

package event

import (
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"golang.org/x/sys/windows"
)

// Source is the type that designates the provenance of the event
type Source uint8

const (
	// SystemLogger event is emitted by the system provider.
	SystemLogger Source = iota
	// SecurityTelemetryLogger event is emitted by the combination of multiple providers.
	// Most notably, DNS, and kernel audit API providers are in charge of publishing the
	// events.
	SecurityTelemetryLogger
)

// Type identifies an event type.
type Type uint16

var (
	// ProcessEventGUID represents process provider event GUID
	ProcessEventGUID = windows.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}
	// ThreadEventGUID represents thread provider event GUID
	ThreadEventGUID = windows.GUID{Data1: 0x3d6fa8d1, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}
	// ModuleEventGUID represents module provider event GUID
	ModuleEventGUID = windows.GUID{Data1: 0x2cb15d1d, Data2: 0x5fc1, Data3: 0x11d2, Data4: [8]byte{0xab, 0xe1, 0x0, 0xa0, 0xc9, 0x11, 0xf5, 0x18}}
	// FileEventGUID represents file provider event GUID
	FileEventGUID = windows.GUID{Data1: 0x90cbdc39, Data2: 0x4a3e, Data3: 0x11d1, Data4: [8]byte{0x84, 0xf4, 0x0, 0x0, 0xf8, 0x04, 0x64, 0xe3}}
	// RegistryEventGUID represents registry provider event GUID
	RegistryEventGUID = windows.GUID{Data1: 0xae53722e, Data2: 0xc863, Data3: 0x11d2, Data4: [8]byte{0x86, 0x59, 0x0, 0xc0, 0x4f, 0xa3, 0x21, 0xa1}}
	// NetworkTCPEventGUID represents network TCP provider event GUID
	NetworkTCPEventGUID = windows.GUID{Data1: 0x9a280ac0, Data2: 0xc8e0, Data3: 0x11d1, Data4: [8]byte{0x84, 0xe2, 0x0, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}}
	// NetworkUDPEventGUID represents network UDP provider event GUID
	NetworkUDPEventGUID = windows.GUID{Data1: 0xbf3a50c5, Data2: 0xa9c9, Data3: 0x4988, Data4: [8]byte{0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}}
	// MemoryEventGUID represents memory provider event GUID
	MemoryEventGUID = windows.GUID{Data1: 0x3d6fa8d3, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}
	// AuditAPIEventGUID represents audit API calls event GUID
	AuditAPIEventGUID = windows.GUID{Data1: 0xe02a841c, Data2: 0x75a3, Data3: 0x4fa7, Data4: [8]byte{0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}}
	// DNSEventGUID represents DNS provider event GUID
	DNSEventGUID = windows.GUID{Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9, Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}}
	// ProcessKernelEventGUID represents the Process Kernel event GUID
	ProcessKernelEventGUID = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b, Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}
	// RegistryKernelEventGUID represents the Registry Kernel event GUID
	RegistryKernelEventGUID = windows.GUID{Data1: 0x70eb4f03, Data2: 0xc1de, Data3: 0x4f73, Data4: [8]byte{0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}}
	// StackWalkEventGUID represents the StackWalk event GUID
	StackWalkEventGUID = windows.GUID{Data1: 0xdef2fe46, Data2: 0x7bd6, Data3: 0x4b80, Data4: [8]byte{0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}}
)

const (
	Unknown Type = iota
	CreateProcess
	TerminateProcess
	ProcessRundown
	OpenProcess
	CreateProcessInternal  // only purpose of this event is to enrich the process state with some extra attributes
	ProcessRundownInternal // populates the snapshotter for events running in the Security Telemetry session
	CreateThread
	TerminateThread
	ThreadRundown
	OpenThread
	SetThreadContext
	UnloadModule
	LoadModule
	ModuleRundown
	LoadModuleInternal // only purpose is to populate the module state for events running in the Security Telemetry session
	RegCreateKey
	RegOpenKey
	RegDeleteKey
	RegQueryKey
	RegSetValue
	RegSetValueInternal // internal event that is used to enrich the corresponding public RegSetValue event with captured data
	RegDeleteValue
	RegQueryValue
	RegCloseKey
	RegCreateKCB
	RegDeleteKCB
	RegKCBRundown
	CreateFile
	ReleaseFile
	CloseFile
	ReadFile
	WriteFile
	SetFileInformation
	DeleteFile
	RenameFile
	EnumDirectory
	FileRundown
	FileOpEnd
	Accept
	Send
	Recv
	Connect
	Disconnect
	Reconnect
	Retransmit
	QueryDNS
	ReplyDNS
	MapViewOfSection
	UnmapViewOfSection
	MapViewSectionRundown
	VirtualAlloc
	VirtualFree
	CreateSymbolicLinkObject
	StackWalk
	MaxEvent
)

const (
	CreateProcessID          uint8  = 1
	CreateProcessInternalID  uint16 = 1
	TerminateProcessID       uint8  = 2
	ProcessRundownID         uint8  = 3
	OpenProcessID            uint16 = 5
	ProcessRundownInternalID uint16 = 15

	CreateThreadID     uint8  = 1
	TerminateThreadID  uint8  = 2
	ThreadRundownID    uint8  = 3
	SetThreadContextID uint16 = 4
	OpenThreadID       uint16 = 6

	UnloadModuleID       uint8  = 2
	ModuleRundownID      uint8  = 3
	LoadModuleInternalID uint16 = 5
	LoadModuleID         uint8  = 10

	FileRundownID        uint8 = 36
	MapViewFileID        uint8 = 37
	UnmapViewFileID      uint8 = 38
	MapFileRundownID     uint8 = 39
	CreateFileID         uint8 = 64
	ReleaseFileID        uint8 = 65
	CloseFileID          uint8 = 66
	ReadFileID           uint8 = 67
	WriteFileID          uint8 = 68
	SetFileInformationID uint8 = 69
	DeleteFileID         uint8 = 70
	RenameFileID         uint8 = 71
	EnumDirectoryID      uint8 = 72
	FileOpEndID          uint8 = 76

	RegCreateKeyID        uint8  = 10
	RegOpenKeyID          uint8  = 11
	RegDeleteKeyID        uint8  = 12
	RegQueryKeyID         uint8  = 13
	RegSetValueID         uint8  = 14
	RegDeleteValueID      uint8  = 15
	RegQueryValueID       uint8  = 16
	RegCreateKCBID        uint8  = 22
	RegDeleteKCBID        uint8  = 23
	RegKCBRundownID       uint8  = 25
	RegCloseKeyID         uint8  = 27
	RegSetValueInternalID uint16 = 36

	AcceptTCPv4ID     uint8 = 15
	AcceptTCPv6ID     uint8 = 31
	SendV4ID          uint8 = 10
	SendV6ID          uint8 = 26
	RecvV4ID          uint8 = 11
	RecvV6ID          uint8 = 27
	ConnectTCPv4ID    uint8 = 12
	ConnectTCPv6ID    uint8 = 28
	DisconnectTCPv4ID uint8 = 13
	DisconnectTCPv6ID uint8 = 29
	ReconnectTCPv4ID  uint8 = 16
	ReconnectTCPv6ID  uint8 = 32
	RetransmitTCPv4ID uint8 = 14
	RetransmitTCPv6ID uint8 = 30

	VirtualAllocID uint8 = 98
	VirtualFreeID  uint8 = 99

	QueryDNSID uint16 = 3006
	ReplyDNSID uint16 = 3008

	CreateSymbolicLinkObjectID uint16 = 3

	StackWalkID uint8 = 32
)

// NewTypeFromEventRecord derives the event type from the Data1 member of the provider GUID
// and the opcode/event ID integer.
// Go only jump-tables switches over integer types and only when case values are reasonably
// dense. A switch over provider ID which is GUID struct compiles to a sequential chain of
// struct-equality compares instead of a jump table.
// So we split the GUID into a fast-reject key and switch on that instead. The first member of
// the GUID (Data1) is a dense uint32 integer and is certainly unique across all providers.
func NewTypeFromEventRecord(r *etw.EventRecord) Type {
	switch r.Header.ProviderID.Data1 {
	case RegistryEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case RegCreateKeyID:
			return RegCreateKey
		case RegOpenKeyID:
			return RegOpenKey
		case RegDeleteKeyID:
			return RegDeleteKey
		case RegQueryKeyID:
			return RegQueryKey
		case RegSetValueID:
			return RegSetValue
		case RegDeleteValueID:
			return RegDeleteValue
		case RegQueryValueID:
			return RegQueryValue
		case RegCreateKCBID:
			return RegCreateKCB
		case RegDeleteKCBID:
			return RegDeleteKCB
		case RegKCBRundownID:
			return RegKCBRundown
		case RegCloseKeyID:
			return RegCloseKey
		}
	case FileEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case FileRundownID:
			return FileRundown
		case MapViewFileID:
			return MapViewOfSection
		case UnmapViewFileID:
			return UnmapViewOfSection
		case MapFileRundownID:
			return MapViewSectionRundown
		case CreateFileID:
			return CreateFile
		case ReleaseFileID:
			return ReleaseFile
		case CloseFileID:
			return CloseFile
		case ReadFileID:
			return ReadFile
		case WriteFileID:
			return WriteFile
		case SetFileInformationID:
			return SetFileInformation
		case DeleteFileID:
			return DeleteFile
		case RenameFileID:
			return RenameFile
		case EnumDirectoryID:
			return EnumDirectory
		case FileOpEndID:
			return FileOpEnd
		}
	case AuditAPIEventGUID.Data1:
		switch r.Header.EventDescriptor.ID {
		case OpenProcessID:
			return OpenProcess
		case OpenThreadID:
			return OpenThread
		case SetThreadContextID:
			return SetThreadContext
		case CreateSymbolicLinkObjectID:
			return CreateSymbolicLinkObject
		}
	case StackWalkEventGUID.Data1:
		return StackWalk
	case MemoryEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case VirtualAllocID:
			return VirtualAlloc
		case VirtualFreeID:
			return VirtualFree
		}
	case NetworkTCPEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case AcceptTCPv4ID, AcceptTCPv6ID:
			return Accept
		case SendV4ID, SendV6ID:
			return Send
		case RecvV4ID, RecvV6ID:
			return Recv
		case ConnectTCPv4ID, ConnectTCPv6ID:
			return Connect
		case DisconnectTCPv4ID, DisconnectTCPv6ID:
			return Disconnect
		case ReconnectTCPv4ID, ReconnectTCPv6ID:
			return Reconnect
		case RetransmitTCPv4ID, RetransmitTCPv6ID:
			return Retransmit
		}
	case NetworkUDPEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case SendV4ID, SendV6ID:
			return Send
		case RecvV4ID, RecvV6ID:
			return Recv
		}
	case DNSEventGUID.Data1:
		switch r.Header.EventDescriptor.ID {
		case QueryDNSID:
			return QueryDNS
		case ReplyDNSID:
			return ReplyDNS
		}
	case ProcessEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case CreateProcessID:
			return CreateProcess
		case TerminateProcessID:
			return TerminateProcess
		case ProcessRundownID:
			return ProcessRundown
		}
	case ProcessKernelEventGUID.Data1:
		switch r.Header.EventDescriptor.ID {
		case CreateProcessInternalID:
			return CreateProcessInternal
		case ProcessRundownInternalID:
			return ProcessRundownInternal
		case LoadModuleInternalID:
			return LoadModuleInternal
		}
	case ModuleEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case UnloadModuleID:
			return UnloadModule
		case ModuleRundownID:
			return ModuleRundown
		case LoadModuleID:
			return LoadModule
		}
	case ThreadEventGUID.Data1:
		switch r.Header.EventDescriptor.Opcode {
		case CreateThreadID:
			return CreateThread
		case TerminateThreadID:
			return TerminateThread
		case ThreadRundownID:
			return ThreadRundown
		}
	}
	return Unknown
}

// String returns the event type string representation.
func (t Type) String() string { return table[t].Name }

// Uint coerces the type to pointer-sized unsigned integer.
func (t Type) Uint() uint { return uint(t) }

// OnlyState determines whether the event type is solely used for state management.
func (t Type) OnlyState() bool { return table[t].Flags&OnlyState != 0 }

// IsRundown indicates if this type represents a rundown event that seeds the state.
func (t Type) StateSnapshot() bool { return table[t].Flags&StateSnapshot != 0 }

// WaitStack determines if the event waits for call stack return addresses.
func (t Type) WaitStack() bool { return table[t].Flags&WaitStack != 0 }

// EventID produces a native ETW classic event identifier to
// indicate which event types are enabled for stack walk tracing.
func (t Type) EventID() etw.ClassicEventID {
	switch t {
	case CreateProcess:
		return etw.ClassicEventID{GUID: ProcessEventGUID, Type: CreateProcessID}
	case CreateThread:
		return etw.ClassicEventID{GUID: ThreadEventGUID, Type: CreateThreadID}
	case TerminateThread:
		return etw.ClassicEventID{GUID: ThreadEventGUID, Type: TerminateThreadID}
	case LoadModule:
		return etw.ClassicEventID{GUID: ProcessEventGUID, Type: LoadModuleID}
	case CreateFile:
		return etw.ClassicEventID{GUID: FileEventGUID, Type: CreateFileID}
	case DeleteFile:
		return etw.ClassicEventID{GUID: FileEventGUID, Type: DeleteFileID}
	case RenameFile:
		return etw.ClassicEventID{GUID: FileEventGUID, Type: RenameFileID}
	case RegCreateKey:
		return etw.ClassicEventID{GUID: RegistryEventGUID, Type: RegCreateKeyID}
	case RegDeleteKey:
		return etw.ClassicEventID{GUID: RegistryEventGUID, Type: RegDeleteKeyID}
	case RegSetValue:
		return etw.ClassicEventID{GUID: RegistryEventGUID, Type: RegSetValueID}
	case RegDeleteValue:
		return etw.ClassicEventID{GUID: RegistryEventGUID, Type: RegDeleteValueID}
	case VirtualAlloc:
		return etw.ClassicEventID{GUID: MemoryEventGUID, Type: VirtualAllocID}
	default:
		return etw.ClassicEventID{}
	}
}

// color return the colorized event type to render by the color formatter.
func (t Type) color() string {
	switch t {
	case CreateFile, ReadFile, CloseFile, SetFileInformation:
		return colorizer.SpanBold(colorizer.Cyan, t.String())
	case RenameFile:
		return colorizer.SpanBold(colorizer.Amber, t.String())
	case WriteFile:
		return colorizer.SpanBold(colorizer.Teal, t.String())
	case DeleteFile:
		return colorizer.SpanBold(colorizer.Red, t.String())
	case RegOpenKey, RegCreateKey, RegQueryValue, RegQueryKey:
		return colorizer.SpanBold(colorizer.Yellow, t.String())
	case RegDeleteKey, RegDeleteValue:
		return colorizer.SpanBold(colorizer.Red, t.String())
	case RegSetValue:
		return colorizer.SpanBold(colorizer.Amber, t.String())
	case CreateProcess, OpenProcess:
		return colorizer.SpanBold(colorizer.Green, t.String())
	case TerminateProcess:
		return colorizer.SpanBold(colorizer.Red, t.String())
	case CreateThread, OpenThread:
		return colorizer.SpanBold(colorizer.Green, t.String())
	case TerminateThread:
		return colorizer.SpanBold(colorizer.Red, t.String())
	case SetThreadContext:
		return colorizer.SpanBold(colorizer.Amber, t.String())
	case LoadModule, UnloadModule:
		return colorizer.SpanBold(colorizer.Magenta, t.String())
	case Send, Recv:
		return colorizer.SpanBold(colorizer.Blue, t.String())
	case Connect:
		return colorizer.SpanBold(colorizer.Teal, t.String())
	case Disconnect:
		return colorizer.SpanBold(colorizer.Blue, t.String())
	case Accept:
		return colorizer.SpanBold(colorizer.Teal, t.String())
	case QueryDNS, ReplyDNS:
		return colorizer.SpanBold(colorizer.Indigo, t.String())
	case VirtualAlloc, VirtualFree, MapViewOfSection, UnmapViewOfSection:
		return colorizer.SpanBold(colorizer.Magenta, t.String())
	case CreateSymbolicLinkObject:
		return colorizer.SpanBold(colorizer.Lavender, t.String())
	default:
		return colorizer.SpanBold(colorizer.White, t.String())
	}
}

// arrow renders the prefix arrow according to event severity.
// Events are grouped by destructive, mutate, read, and housekeeping
// severities. Destructive severity covers events that irreversibly
// alter system state: process termination, file deletion, registry
// key deletion, code injection.
//
// Mutate covers write/create operations: file writes, registry value
// sets, process creation, thread context changes.
//
// Read covers read/query/open operations that consume but do not
// alter state. Finally, houskeeping covers close/cleanup
// events that are expected noise in a healthy system.
func (t Type) arrow() string {
	var clr uint8
	switch t {
	case TerminateProcess, TerminateThread, DeleteFile, RegDeleteKey,
		RegDeleteValue, UnloadModule, VirtualFree, UnmapViewOfSection:
		clr = colorizer.Red
	case CreateProcess, CreateFile, WriteFile, RenameFile, SetFileInformation,
		RegCreateKey, RegSetValue, CreateThread, SetThreadContext, VirtualAlloc,
		MapViewOfSection, Connect, Accept, Send:
		clr = colorizer.Amber
	case ReadFile, EnumDirectory, LoadModule, RegOpenKey, RegQueryKey, RegQueryValue,
		OpenProcess, OpenThread, Recv:
		clr = colorizer.Teal
	case QueryDNS, ReplyDNS:
		clr = colorizer.Indigo
	default:
		clr = colorizer.Gray
	}
	return colorizer.SpanBold(clr, "› ")
}
