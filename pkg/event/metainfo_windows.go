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
	"cmp"
	"slices"
)

// Flags represents the event flags
type Flags uint8

const (
	// OnlyState indicates the event produces internal state
	// and is never published to the event stream.
	OnlyState Flags = 1 << 1

	// StateSnapshot indicates that the event is published once
	// at startup time and populates the internal state.
	StateSnapshot Flags = 1 << 2

	// WaitStack indicates that the event awaits the stack walk
	// event that carries call stack return addresses.
	WaitStack Flags = 1 << 3
)

// Info describes the event meta info such as human-readable name, category and description.
type Info struct {
	// Name is the human-readable representation of the event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which event pertains. (e.g. process, network)
	Category Category
	// Subcategory designates the event subcategory if any. For example, the network category
	// can be further subcategorized, such as DNS subcategory.
	Subcategory Subcategory
	// Source describes the event source origin for this event. For example, if it was captured
	// from the NT Kernel Logger or a different event source.
	Source Source
	// Description is the short explanation that describes the purpose of the event.
	Description string
	// Flags describes additional properties of the event.
	Flags Flags
}

var table = [MaxEvent]Info{
	CreateProcess:          {Name: "CreateProcess", Category: Process, Source: SystemLogger, Description: "Creates a new process and its primary thread", Flags: WaitStack},
	TerminateProcess:       {Name: "TerminateProcess", Category: Process, Source: SystemLogger, Description: "Terminates the process and all of its threads"},
	OpenProcess:            {Name: "OpenProcess", Category: Process, Source: SecurityTelemetryLogger, Description: "Opens the process handle"},
	ProcessRundown:         {Name: "ProcessRundown", Category: Process, Source: SecurityTelemetryLogger, Description: "Builds the snapshot state of running processes in the system.", Flags: OnlyState | StateSnapshot},
	CreateProcessInternal:  {Name: "CreateProcessInternal", Category: Process, Source: SystemLogger, Description: "Only purpose of this event is to enrich the process state with some extra attributes. Never published to the event stream", Flags: OnlyState},
	ProcessRundownInternal: {Name: "ProcessRundownInternal", Category: Process, Source: SecurityTelemetryLogger, Description: "Opens the process handle", Flags: OnlyState | StateSnapshot},

	CreateThread:     {Name: "CreateThread", Category: Thread, Source: SystemLogger, Description: "Creates a thread to execute within the virtual address space of the calling process", Flags: WaitStack},
	TerminateThread:  {Name: "TerminateThread", Category: Thread, Source: SystemLogger, Description: "Terminates a thread within the process", Flags: WaitStack},
	OpenThread:       {Name: "OpenThread", Category: Thread, Source: SecurityTelemetryLogger, Description: "Opens the thread handle"},
	SetThreadContext: {Name: "SetThreadContext", Category: Thread, Source: SecurityTelemetryLogger, Description: "Sets the thread context"},
	StackWalk:        {Name: "StackWalk", Category: Thread, Source: SystemLogger, Description: "Delivers call stack return addresses. Never published to the event stream", Flags: OnlyState},
	ThreadRundown:    {Name: "ThreadRundown", Category: Thread, Source: SystemLogger, Description: "Builds the snapshot state of running threads in the system", Flags: OnlyState | StateSnapshot},

	UnloadModule:       {Name: "UnloadModule", Category: Module, Source: SystemLogger, Description: "Unloads the module from the address space of the calling process"},
	LoadModule:         {Name: "LoadModule", Category: Module, Source: SystemLogger, Description: "Loads the module into the address space of the calling process", Flags: WaitStack},
	ModuleRundown:      {Name: "ModuleRundown", Category: Module, Source: SystemLogger, Description: "Builds the snapshot of loaded modules in the system", Flags: OnlyState | StateSnapshot},
	LoadModuleInternal: {Name: "LoadModuleInternal", Category: Module, Source: SecurityTelemetryLogger, Description: "Only purpose is to populate the module state. Never published to the event stream", Flags: OnlyState},

	RegCreateKey:        {Name: "RegCreateKey", Category: Registry, Source: SystemLogger, Description: "Creates a registry key or opens it if the key already exists", Flags: WaitStack},
	RegOpenKey:          {Name: "RegOpenKey", Category: Registry, Source: SystemLogger, Description: "Opens the registry key"},
	RegDeleteKey:        {Name: "RegDeleteKey", Category: Registry, Source: SystemLogger, Description: "Removes the registry key", Flags: WaitStack},
	RegQueryKey:         {Name: "RegQueryKey", Category: Registry, Source: SystemLogger, Description: "Enumerates subkeys of the parent key"},
	RegSetValue:         {Name: "RegSetValue", Category: Registry, Source: SystemLogger, Description: "Sets the data for the value of a registry key", Flags: WaitStack},
	RegSetValueInternal: {Name: "RegSetValueInternal", Category: Registry, Source: SecurityTelemetryLogger, Description: "Closes the registry key", Flags: OnlyState},
	RegDeleteValue:      {Name: "RegDeleteValue", Category: Registry, Source: SystemLogger, Description: "Removes the registry value", Flags: WaitStack},
	RegQueryValue:       {Name: "RegQueryValue", Category: Registry, Source: SystemLogger, Description: "Reads the data for the value of a registry key"},
	RegCloseKey:         {Name: "RegCloseKey", Category: Registry, Source: SystemLogger, Description: "Closes the registry key. Never published to the event stream", Flags: OnlyState},
	RegCreateKCB:        {Name: "RegCreateKCB", Category: Registry, Source: SystemLogger, Description: "Create the Key Control Block. Never published to the event stream", Flags: OnlyState},
	RegDeleteKCB:        {Name: "RegDeleteKCB", Category: Registry, Source: SystemLogger, Description: "Removes the Key Control Block. Never published to the event stream", Flags: OnlyState},
	RegKCBRundown:       {Name: "RegKCBRundown", Category: Registry, Source: SystemLogger, Description: "Builds the snapshot of existing Key Control Block objects", Flags: OnlyState | StateSnapshot},

	CreateFile:         {Name: "CreateFile", Category: File, Source: SystemLogger, Description: "Creates or opens a new file, directory, I/O device, pipe, console"},
	ReleaseFile:        {Name: "ReleaseFile", Category: File, Source: SystemLogger, Description: "Closes the last handle to the file object. Never published to the event stream", Flags: OnlyState},
	CloseFile:          {Name: "CloseFile", Category: File, Source: SystemLogger, Description: "Closes the file handle. Never published to the event stream", Flags: OnlyState},
	ReadFile:           {Name: "ReadFile", Category: File, Source: SystemLogger, Description: "Reads data from the file or I/O device"},
	WriteFile:          {Name: "WriteFile", Category: File, Source: SystemLogger, Description: "Writes data to the file or I/O device"},
	SetFileInformation: {Name: "SetFileInformation", Category: File, Source: SystemLogger, Description: "Sets the file meta information"},
	DeleteFile:         {Name: "DeleteFile", Category: File, Source: SystemLogger, Description: "Removes the file from the file system", Flags: WaitStack},
	RenameFile:         {Name: "RenameFile", Category: File, Source: SystemLogger, Description: "Changes the file name", Flags: WaitStack},
	EnumDirectory:      {Name: "EnumDirectory", Category: File, Source: SystemLogger, Description: "Enumerates a directory or dispatches a directory change notification to registered listeners"},
	FileRundown:        {Name: "FileRundown", Category: File, Source: SystemLogger, Description: "Builds the snapshot of existing file objects", Flags: OnlyState | StateSnapshot},
	FileOpEnd:          {Name: "FileOpEnd", Category: File, Source: SystemLogger, Description: "Reports the I/O request packet status. Never published to the event stream", Flags: OnlyState},

	Accept:     {Name: "Accept", Category: Network, Source: SystemLogger, Description: "Accepts the connection request from the socket queue"},
	Send:       {Name: "Send", Category: Network, Source: SystemLogger, Description: "Sends data over the wire"},
	Recv:       {Name: "Recv", Category: Network, Source: SystemLogger, Description: "Receives data from the socket"},
	Connect:    {Name: "Connect", Category: Network, Source: SystemLogger, Description: "Connects establishes a connection to the socket"},
	Disconnect: {Name: "Disconnect", Category: Network, Source: SystemLogger, Description: "Terminates data reception on the socket"},
	Reconnect:  {Name: "Reconnect", Category: Network, Source: SystemLogger, Description: "Reconnects to the socket"},
	Retransmit: {Name: "Retransmit", Category: Network, Source: SystemLogger, Description: "Retransmits unacknowledged TCP segments"},
	QueryDNS:   {Name: "QueryDns", Category: Network, Subcategory: DNS, Source: SecurityTelemetryLogger, Description: "Sends a DNS query to the name server"},
	ReplyDNS:   {Name: "ReplyDNS", Category: Network, Subcategory: DNS, Source: SecurityTelemetryLogger, Description: "Receives the response from the DNS server"},

	MapViewOfSection:      {Name: "MapViewOfSection", Category: Memory, Source: SystemLogger, Description: "Maps a view of a file mapping into the address space of a calling process"},
	UnmapViewOfSection:    {Name: "UnmapViewOfSection", Category: Memory, Source: SystemLogger, Description: "Unmaps a mapped view of a file from the calling process's address space"},
	MapViewSectionRundown: {Name: "MapViewSectionRundown", Category: Memory, Source: SystemLogger, Description: "Builds the snapshot of existing memory section views", Flags: OnlyState | StateSnapshot},
	VirtualAlloc:          {Name: "VirtualAlloc", Category: Memory, Source: SystemLogger, Description: "Reserves, commits, or changes the state of a region of memory within the process virtual address space", Flags: WaitStack},
	VirtualFree:           {Name: "VirtualFree", Category: Memory, Source: SystemLogger, Description: "Releases or decommits a region of memory within the process virtual address space"},

	CreateSymbolicLinkObject: {Name: "CreateSymbolicLinkObject", Category: Object, Source: SecurityTelemetryLogger, Description: "Creates the symbolic link within the object manager directory"},
}

// All returns all event types.
func AllTypes() []Type {
	types := make([]Type, 0)
	for i := range table {
		if Type(i) == Unknown {
			continue
		}
		types = append(types, Type(i))
	}
	return types
}

// GetTypeInfo returns metadata about the specified event type.
func GetTypeInfo(typ Type) Info {
	return table[typ]
}

// GetTypesInfo returns event types metadata excluding only-state events.
func GetTypesInfo() []Info {
	t := table[:]
	t = slices.DeleteFunc(t, func(info Info) bool {
		return info.Flags&OnlyState != 0 || info.Name == ""
	})
	slices.SortFunc(t, func(a, b Info) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return t
}

// NameToType converts a human-readable event name to its internal type representation.
func ParseType(s string) (Type, bool) {
	i := slices.IndexFunc(table[:], func(info Info) bool {
		return info.Name == s
	})
	if i == -1 {
		return Unknown, false
	}
	return Type(i), true
}

// IsKnown indicates if the event type is known given the event name.
func IsTypeKnown(s string) (exists bool) {
	_, exists = ParseType(s)
	return
}
