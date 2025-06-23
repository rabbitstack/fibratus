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

// Info describes the event meta info such as human-readable name, category and description.
type Info struct {
	// Name is the human-readable representation of the event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which event pertains. (e.g. process, net)
	Category Category
	// Description is the short explanation that describes the purpose of the event.
	Description string
}

var events = map[Type]Info{
	CreateProcess:            {"CreateProcess", Process, "Creates a new process and its primary thread"},
	TerminateProcess:         {"TerminateProcess", Process, "Terminates the process and all of its threads"},
	OpenProcess:              {"OpenProcess", Process, "Opens the process handle"},
	CreateThread:             {"CreateThread", Thread, "Creates a thread to execute within the virtual address space of the calling process"},
	TerminateThread:          {"TerminateThread", Thread, "Terminates a thread within the process"},
	OpenThread:               {"OpenThread", Thread, "Opens the thread handle"},
	SetThreadContext:         {"SetThreadContext", Thread, "Sets the thread context"},
	ReadFile:                 {"ReadFile", File, "Reads data from the file or I/O device"},
	WriteFile:                {"WriteFile", File, "Writes data to the file or I/O device"},
	CreateFile:               {"CreateFile", File, "Creates or opens a file or I/O device"},
	CloseFile:                {"CloseFile", File, "Closes the file handle"},
	DeleteFile:               {"DeleteFile", File, "Removes the file from the file system"},
	RenameFile:               {"RenameFile", File, "Changes the file name"},
	SetFileInformation:       {"SetFileInformation", File, "Sets the file meta information"},
	EnumDirectory:            {"EnumDirectory", File, "Enumerates a directory or dispatches a directory change notification to registered listeners"},
	RegCreateKey:             {"RegCreateKey", Registry, "Creates a registry key or opens it if the key already exists"},
	RegOpenKey:               {"RegOpenKey", Registry, "Opens the registry key"},
	RegCloseKey:              {"RegCloseKey", Registry, "Closes the registry key"},
	RegSetValue:              {"RegSetValue", Registry, "Sets the data for the value of a registry key"},
	RegQueryValue:            {"RegQueryValue", Registry, "Reads the data for the value of a registry key"},
	RegQueryKey:              {"RegQueryKey", Registry, "Enumerates subkeys of the parent key"},
	RegDeleteKey:             {"RegDeleteKey", Registry, "Removes the registry key"},
	RegDeleteValue:           {"RegDeleteValue", Registry, "Removes the registry value"},
	AcceptTCPv4:              {"Accept", Net, "Accepts the connection request from the socket queue"},
	AcceptTCPv6:              {"Accept", Net, "Accepts the connection request from the socket queue"},
	SendTCPv4:                {"Send", Net, "Sends data over the wire"},
	SendTCPv6:                {"Send", Net, "Sends data over the wire"},
	SendUDPv4:                {"Send", Net, "Sends data over the wire"},
	SendUDPv6:                {"Send", Net, "Sends data over the wire"},
	RecvTCPv4:                {"Recv", Net, "Receives data from the socket"},
	RecvTCPv6:                {"Recv", Net, "Receives data from the socket"},
	RecvUDPv4:                {"Recv", Net, "Receives data from the socket"},
	RecvUDPv6:                {"Recv", Net, "Receives data from the socket"},
	ConnectTCPv4:             {"Connect", Net, "Connects establishes a connection to the socket"},
	ConnectTCPv6:             {"Connect", Net, "Connects establishes a connection to the socket"},
	DisconnectTCPv4:          {"Disconnect", Net, "Terminates data reception on the socket"},
	DisconnectTCPv6:          {"Disconnect", Net, "Terminates data reception on the socket"},
	ReconnectTCPv4:           {"Reconnect", Net, "Reconnects to the socket"},
	ReconnectTCPv6:           {"Reconnect", Net, "Reconnects to the socket"},
	RetransmitTCPv4:          {"Retransmit", Net, "Retransmits unacknowledged TCP segments"},
	RetransmitTCPv6:          {"Retransmit", Net, "Retransmits unacknowledged TCP segments"},
	LoadImage:                {"LoadImage", Image, "Loads the module into the address space of the calling process"},
	UnloadImage:              {"UnloadImage", Image, "Unloads the module from the address space of the calling process"},
	CreateHandle:             {"CreateHandle", Handle, "Creates a new handle"},
	CloseHandle:              {"CloseHandle", Handle, "Closes the handle"},
	DuplicateHandle:          {"DuplicateHandle", Handle, "Duplicates the handle"},
	VirtualAlloc:             {"VirtualAlloc", Mem, "Reserves, commits, or changes the state of a region of memory within the process virtual address space"},
	VirtualFree:              {"VirtualFree", Mem, "Releases or decommits a region of memory within the process virtual address space"},
	MapViewFile:              {"MapViewFile", File, "Maps a view of a file mapping into the address space of a calling process"},
	UnmapViewFile:            {"UnmapViewFile", File, "Unmaps a mapped view of a file from the calling process's address space"},
	QueryDNS:                 {"QueryDns", Net, "Sends a DNS query to the name server"},
	ReplyDNS:                 {"ReplyDNS", Net, "Receives the response from the DNS server"},
	CreateSymbolicLinkObject: {"CreateSymbolicLinkObject", Object, "Creates the symbolic link within the object manager directory"},
	SubmitThreadpoolWork:     {"SubmitThreadpoolWork", Threadpool, "Enqueues the work item to the thread pool"},
	SubmitThreadpoolCallback: {"SubmitThreadpoolCallback", Threadpool, "Submits the thread pool callback for execution within the work item"},
	SetThreadpoolTimer:       {"SetThreadpoolTimer", Threadpool, "Sets the thread pool timer object"},
}

var types = map[string]Type{
	"CreateProcess":            CreateProcess,
	"TerminateProcess":         TerminateProcess,
	"OpenProcess":              OpenProcess,
	"CreateThread":             CreateThread,
	"TerminateThread":          TerminateThread,
	"OpenThread":               OpenThread,
	"SetThreadContext":         SetThreadContext,
	"LoadImage":                LoadImage,
	"UnloadImage":              UnloadImage,
	"CreateFile":               CreateFile,
	"CloseFile":                CloseFile,
	"ReadFile":                 ReadFile,
	"WriteFile":                WriteFile,
	"SetFileInformation":       SetFileInformation,
	"DeleteFile":               DeleteFile,
	"RenameFile":               RenameFile,
	"EnumDirectory":            EnumDirectory,
	"RegCreateKey":             RegCreateKey,
	"RegOpenKey":               RegOpenKey,
	"RegSetValue":              RegSetValue,
	"RegQueryValue":            RegQueryValue,
	"RegQueryKey":              RegQueryKey,
	"RegDeleteKey":             RegDeleteKey,
	"RegDeleteValue":           RegDeleteValue,
	"RegCloseKey":              RegCloseKey,
	"AcceptTCP4":               AcceptTCPv4,
	"AcceptTCP6":               AcceptTCPv6,
	"SendTCP4":                 SendTCPv4,
	"SendTCP6":                 SendTCPv6,
	"SendUDP4":                 SendUDPv4,
	"SendUDP6":                 SendUDPv6,
	"RecvTCP4":                 RecvTCPv4,
	"RecvTCP6":                 RecvTCPv6,
	"RecvUDP4":                 RecvUDPv4,
	"RecvUDP6":                 RecvUDPv6,
	"ConnectTCP4":              ConnectTCPv4,
	"ConnectTCP6":              ConnectTCPv6,
	"ReconnectTCP4":            ReconnectTCPv4,
	"ReconnectTCP6":            ReconnectTCPv6,
	"DisconnectTCP4":           DisconnectTCPv4,
	"DisconnectTCP6":           DisconnectTCPv6,
	"RetransmitTCP4":           RetransmitTCPv4,
	"RetransmitTCP6":           RetransmitTCPv6,
	"CreateHandle":             CreateHandle,
	"CloseHandle":              CloseHandle,
	"DuplicateHandle":          DuplicateHandle,
	"VirtualAlloc":             VirtualAlloc,
	"VirtualFree":              VirtualFree,
	"MapViewFile":              MapViewFile,
	"UnmapViewFile":            UnmapViewFile,
	"QueryDns":                 QueryDNS,
	"ReplyDns":                 ReplyDNS,
	"CreateSymbolicLinkObject": CreateSymbolicLinkObject,
	"SubmitThreadpoolWork":     SubmitThreadpoolWork,
	"SubmitThreadpoolCallback": SubmitThreadpoolCallback,
	"SetThreadpoolTimer":       SetThreadpoolTimer,
}

// indexedEvents keeps the slice of event infos. When the
// new event type is added, MAKE SURE TO ADD the event info
// at the END of the slice. This way the event index is guaranteed
// to remain static which is important for eventlog message identifiers.
var indexedEvents = []Info{
	events[CreateProcess],
	events[TerminateProcess],
	events[OpenProcess],
	events[CreateThread],
	events[TerminateThread],
	events[OpenThread],
	events[SetThreadContext],
	events[LoadImage],
	events[UnloadImage],
	events[CreateFile],
	events[CloseFile],
	events[ReadFile],
	events[WriteFile],
	events[SetFileInformation],
	events[DeleteFile],
	events[RenameFile],
	events[EnumDirectory],
	events[RegCreateKey],
	events[RegOpenKey],
	events[RegSetValue],
	events[RegQueryValue],
	events[RegQueryKey],
	events[RegDeleteKey],
	events[RegDeleteValue],
	events[AcceptTCPv4],
	events[AcceptTCPv6],
	events[SendTCPv4],
	events[SendTCPv6],
	events[SendUDPv4],
	events[SendUDPv6],
	events[RecvTCPv4],
	events[RecvTCPv6],
	events[RecvUDPv4],
	events[RecvUDPv6],
	events[ConnectTCPv4],
	events[ConnectTCPv6],
	events[ReconnectTCPv4],
	events[ReconnectTCPv6],
	events[DisconnectTCPv4],
	events[DisconnectTCPv6],
	events[RetransmitTCPv4],
	events[RetransmitTCPv6],
	events[CreateHandle],
	events[CloseHandle],
	events[DuplicateHandle],
	events[VirtualAlloc],
	events[VirtualFree],
	events[MapViewFile],
	events[UnmapViewFile],
	events[QueryDNS],
	events[ReplyDNS],
	events[CreateSymbolicLinkObject],
	events[SubmitThreadpoolWork],
	events[SubmitThreadpoolCallback],
	events[SetThreadpoolTimer],
}

// All returns all event types.
func All() []Type {
	s := make([]Type, 0, len(types))
	for _, typ := range types {
		s = append(s, typ)
	}
	return s
}

// AllWithState returns all event types +
// event types used for state management.
func AllWithState() []Type {
	s := All()

	s = append(s, ProcessRundown)
	s = append(s, ThreadRundown)
	s = append(s, ImageRundown)
	s = append(s, FileRundown)
	s = append(s, RegKCBRundown)
	s = append(s, RegCreateKCB)
	s = append(s, RegDeleteKCB)
	s = append(s, FileOpEnd)
	s = append(s, ReleaseFile)
	s = append(s, MapFileRundown)
	s = append(s, StackWalk)
	s = append(s, CreateProcessInternal)
	s = append(s, ProcessRundownInternal)
	s = append(s, LoadImageInternal)

	return s
}

// MaxTypeID returns the maximum event type (hook id) value.
func MaxTypeID() uint16 {
	types := AllWithState()
	ids := make([]uint16, len(types))
	for i, t := range types {
		ids[i] = t.HookID()
	}
	return slices.Max(ids)
}

// TypeToEventInfo maps the event type to the structure storing detailed information about the event.
func TypeToEventInfo(typ Type) Info {
	if info, ok := events[typ]; ok {
		return info
	}
	return Info{Name: "N/A", Category: Unknown}
}

// NameToType converts a human-readable event name to its internal type representation.
func NameToType(name string) Type {
	if typ, ok := types[name]; ok {
		return typ
	}
	return UnknownType
}

// NameToTypes maps the event name to internal type representations, specifically, network
// events that have multiple internal types for a single event name. For example, the Accept
// event name has AcceptTCP4 and AcceptTCP6 types.
func NameToTypes(name string) []Type {
	switch name {
	case "Accept":
		return []Type{AcceptTCPv4, AcceptTCPv6}
	case "Send":
		return []Type{SendTCPv4, SendTCPv6, SendUDPv4, SendUDPv6}
	case "Recv":
		return []Type{RecvTCPv4, RecvTCPv6, RecvUDPv4, RecvUDPv6}
	case "Connect":
		return []Type{ConnectTCPv4, ConnectTCPv6}
	case "Reconnect":
		return []Type{ReconnectTCPv4, ReconnectTCPv6}
	case "Disconnect":
		return []Type{DisconnectTCPv4, DisconnectTCPv6}
	case "Retransmit":
		return []Type{RetransmitTCPv4, RetransmitTCPv6}
	default:
		return []Type{NameToType(name)}
	}
}

// GetTypesMeta returns event types metadata.
func GetTypesMeta() []Info {
	typs := make([]Info, 0)
outer:
	for _, ev := range events {
		for _, typ := range typs {
			if typ.Name == ev.Name {
				continue outer
			}
		}
		typs = append(typs, ev)
	}
	slices.SortFunc(typs, func(a, b Info) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return typs
}

// GetTypesMetaIndexed returns indexed event types metadata
// that is guaranteed to always return the same event indices.
func GetTypesMetaIndexed() []Info { return indexedEvents }
