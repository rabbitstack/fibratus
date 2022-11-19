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

package ktypes

import "sort"

// KeventInfo describes the kernel event meta info such as human-readable name, category
// and event's description.
type KeventInfo struct {
	// Name is the human-readable representation of the event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which event pertains. (e.g. process, net)
	Category Category
	// Description is the short explanation that describes the purpose of the event.
	Description string
}

var kevents = map[Ktype]KeventInfo{
	CreateProcess:      {"CreateProcess", Process, "Creates a new process and its primary thread"},
	TerminateProcess:   {"TerminateProcess", Process, "Terminates the process and all of its threads"},
	OpenProcess:        {"OpenProcess", Process, "Opens the process handle"},
	CreateThread:       {"CreateThread", Thread, "Creates a thread to execute within the virtual address space of the calling process"},
	TerminateThread:    {"TerminateThread", Thread, "Terminates a thread within the process"},
	OpenThread:         {"OpenThread", Thread, "Opens the thread handle"},
	ReadFile:           {"ReadFile", File, "Reads data from the file or I/O device"},
	WriteFile:          {"WriteFile", File, "Writes data to the file or I/O device"},
	CreateFile:         {"CreateFile", File, "Creates or opens a file or I/O device"},
	CloseFile:          {"CloseFile", File, "Closes the file handle"},
	DeleteFile:         {"DeleteFile", File, "Removes the file from the file system"},
	RenameFile:         {"RenameFile", File, "Changes the file name"},
	SetFileInformation: {"SetFileInformation", File, "Sets the file meta information"},
	EnumDirectory:      {"EnumDirectory", File, "Enumerates a directory or dispatches a directory change notification to registered listeners"},
	RegCreateKey:       {"RegCreateKey", Registry, "Creates a registry key or opens it if the key already exists"},
	RegOpenKey:         {"RegOpenKey", Registry, "Opens the registry key"},
	RegCloseKey:        {"RegCloseKey", Registry, "Closes the registry key"},
	RegSetValue:        {"RegSetValue", Registry, "Sets the data for the value of a registry key"},
	RegQueryValue:      {"RegQueryValue", Registry, "Reads the data for the value of a registry key"},
	RegQueryKey:        {"RegQueryKey", Registry, "Enumerates subkeys of the parent key"},
	RegDeleteKey:       {"RegDeleteKey", Registry, "Removes the registry key"},
	RegDeleteValue:     {"RegDeleteValue", Registry, "Removes the registry value"},
	AcceptTCPv4:        {"Accept", Net, "Accepts the connection request from the socket queue"},
	AcceptTCPv6:        {"Accept", Net, "Accepts the connection request from the socket queue"},
	SendTCPv4:          {"Send", Net, "Sends data over the wire"},
	SendTCPv6:          {"Send", Net, "Sends data over the wire"},
	SendUDPv4:          {"Send", Net, "Sends data over the wire"},
	SendUDPv6:          {"Send", Net, "Sends data over the wire"},
	RecvTCPv4:          {"Recv", Net, "Receives data from the socket"},
	RecvTCPv6:          {"Recv", Net, "Receives data from the socket"},
	RecvUDPv4:          {"Recv", Net, "Receives data from the socket"},
	RecvUDPv6:          {"Recv", Net, "Receives data from the socket"},
	ConnectTCPv4:       {"Connect", Net, "Connects establishes a connection to the socket"},
	ConnectTCPv6:       {"Connect", Net, "Connects establishes a connection to the socket"},
	DisconnectTCPv4:    {"Disconnect", Net, "Terminates data reception on the socket"},
	DisconnectTCPv6:    {"Disconnect", Net, "Terminates data reception on the socket"},
	ReconnectTCPv4:     {"Reconnect", Net, "Reconnects to the socket"},
	ReconnectTCPv6:     {"Reconnect", Net, "Reconnects to the socket"},
	RetransmitTCPv4:    {"Retransmit", Net, "Retransmits unacknowledged TCP segments"},
	RetransmitTCPv6:    {"Retransmit", Net, "Retransmits unacknowledged TCP segments"},
	LoadImage:          {"LoadImage", Image, "Loads the module into the address space of the calling process"},
	UnloadImage:        {"UnloadImage", Image, "Unloads the module from the address space of the calling process"},
	CreateHandle:       {"CreateHandle", Handle, "Creates a new handle"},
	CloseHandle:        {"CloseHandle", Handle, "Closes the handle"},
	LoadDriver:         {"LoadDriver", Driver, "Loads the kernel driver"},
}

var ktypes = map[string]Ktype{
	"CreateProcess":      CreateProcess,
	"TerminateProcess":   TerminateProcess,
	"OpenProcess":        OpenProcess,
	"CreateThread":       CreateThread,
	"TerminateThread":    TerminateThread,
	"OpenThread":         OpenThread,
	"LoadImage":          LoadImage,
	"UnloadImage":        UnloadImage,
	"CreateFile":         CreateFile,
	"CloseFile":          CloseFile,
	"ReadFile":           ReadFile,
	"WriteFile":          WriteFile,
	"SetFileInformation": SetFileInformation,
	"DeleteFile":         DeleteFile,
	"RenameFile":         RenameFile,
	"EnumDirectory":      EnumDirectory,
	"RegCreateKey":       RegCreateKey,
	"RegOpenKey":         RegOpenKey,
	"RegSetValue":        RegSetValue,
	"RegQueryValue":      RegQueryValue,
	"RegQueryKey":        RegQueryKey,
	"RegDeleteKey":       RegDeleteKey,
	"RegDeleteValue":     RegDeleteValue,
	//"Accept":             Accept,
	//"Send":               Send,
	//"Recv":               Recv,
	//"Connect":            Connect,
	//"Reconnect":          Reconnect,
	//"Disconnect":         Disconnect,
	//"Retransmit":         Retransmit,
	"CreateHandle": CreateHandle,
	"CloseHandle":  CloseHandle,
	"LoadDriver":   LoadDriver,
}

// KtypeToKeventInfo maps the event type to the structure storing detailed information about the event.
func KtypeToKeventInfo(ktype Ktype) KeventInfo {
	if kinfo, ok := kevents[ktype]; ok {
		return kinfo
	}
	return KeventInfo{Name: "N/A", Category: Unknown}
}

// KeventNameToKtype converts a human-readable event name to its internal type representation.
func KeventNameToKtype(name string) Ktype {
	if ktype, ok := ktypes[name]; ok {
		return ktype
	}
	return UnknownKtype
}

// GetKtypesMeta returns event types metadata.
func GetKtypesMeta() []KeventInfo {
	ktypes := make([]KeventInfo, 0, len(kevents))
	for _, ktyp := range kevents {
		for _, typ := range ktypes {
			if typ.Name == ktyp.Name {
				continue
			}
		}
		ktypes = append(ktypes, ktyp)
	}
	sort.Slice(ktypes, func(i, j int) bool { return ktypes[i].Category < ktypes[j].Category })
	return ktypes
}
