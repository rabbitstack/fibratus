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

// KeventInfo describes the kernel event meta info such as human readable name, category
// and event's description.
type KeventInfo struct {
	// Name is the human-readable representation of the kernel event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which kernel event pertains. (e.g. process, net)
	Category Category
	// Description is the short explanation that describes the purpose of the kernel event.
	Description string
}

var kevents = map[Ktype]KeventInfo{
	CreateProcess:      {"CreateProcess", Process, "Creates a new process and its primary thread"},
	TerminateProcess:   {"TerminateProcess", Process, "Terminates the process and all of its threads"},
	CreateThread:       {"CreateThread", Thread, "Creates a thread to execute within the virtual address space of the calling process"},
	TerminateThread:    {"TerminateThread", Thread, "Terminates a thread within the process"},
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
	RegSetValue:        {"RegSetValue", Registry, "Sets the data for the value of a registry key"},
	RegQueryValue:      {"RegQueryValue", Registry, "Reads the data for the value of a registry key"},
	RegQueryKey:        {"RegQueryKey", Registry, "Enumerates subkeys of the parent key"},
	RegDeleteKey:       {"RegDeleteKey", Registry, "Removes the registry key"},
	RegDeleteValue:     {"RegDeleteValue", Registry, "Removes the registry value"},
	Accept:             {"Accept", Net, "Accepts the connection request from the socket queue"},
	Send:               {"Send", Net, "Sends data over the wire"},
	Recv:               {"Recv", Net, "Receives data from the socket"},
	Connect:            {"Connect", Net, "Connects establishes a connection to the socket"},
	Disconnect:         {"Disconnect", Net, "Terminates data reception on the socket"},
	Reconnect:          {"Reconnect", Net, "Reconnects to the socket"},
	Retransmit:         {"Retransmit", Net, "Retransmits unacknowledged TCP segments"},
	LoadImage:          {"LoadImage", Image, "Loads the module into the address space of the calling process"},
	UnloadImage:        {"UnloadImage", Image, "Unloads the module from the address space of the calling process"},
	CreateHandle:       {"CreateHandle", Handle, "Creates a new handle"},
	CloseHandle:        {"CloseHandle", Handle, "Closes the handle"},
}

var ktypes = map[string]Ktype{
	"CreateProcess":      CreateProcess,
	"TerminateProcess":   TerminateProcess,
	"CreateThread":       CreateThread,
	"TerminateThread":    TerminateThread,
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
	"Accept":             Accept,
	"Send":               Send,
	"Recv":               Recv,
	"Connect":            Connect,
	"Reconnect":          Reconnect,
	"Disconnect":         Disconnect,
	"Retransmit":         Retransmit,
	"CreateHandle":       CreateHandle,
	"CloseHandle":        CloseHandle,
}

// KtypeToKeventInfo maps the kernel event type to a structure that stores detailed information about the event.
func KtypeToKeventInfo(ktype Ktype) KeventInfo {
	if ktype == RegOpenKeyV1 {
		return kevents[RegOpenKey]
	}
	if ktype == AcceptTCPv4 || ktype == AcceptTCPv6 {
		return kevents[Accept]
	}
	if ktype == ConnectTCPv4 || ktype == ConnectTCPv6 {
		return kevents[Connect]
	}
	if ktype == ReconnectTCPv4 || ktype == ReconnectTCPv6 {
		return kevents[Reconnect]
	}
	if ktype == RetransmitTCPv4 || ktype == RetransmitTCPv6 {
		return kevents[Retransmit]
	}
	if ktype == DisconnectTCPv4 || ktype == DisconnectTCPv6 {
		return kevents[Disconnect]
	}
	if ktype == SendTCPv4 || ktype == SendTCPv6 || ktype == SendUDPv4 || ktype == SendUDPv6 {
		return kevents[Send]
	}
	if ktype == RecvTCPv4 || ktype == RecvTCPv6 || ktype == RecvUDPv4 || ktype == RecvUDPv6 {
		return kevents[Recv]
	}

	if kinfo, ok := kevents[ktype]; ok {
		return kinfo
	}
	return KeventInfo{Name: "N/A", Category: Unknown}
}
