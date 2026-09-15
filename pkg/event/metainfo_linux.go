//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

import "slices"

var events = map[Type]Info{
	Execve:         {Name: "execve", Category: Process, Description: "Executes a program"},
	Exit:           {Name: "exit", Category: Process, Description: "Exit all threads in a process"},
	Clone:          {Name: "clone", Category: Process, Description: "Creates a child process or a thread"},
	Openat:         {Name: "openat", Category: File, Description: "Opens or creates a file"},
	Unlink:         {Name: "unlink", Category: File, Description: "Removes a directory entry"},
	Rename:         {Name: "rename", Category: File, Description: "Renames a file"},
	Connect:        {Name: "connect", Category: Net, Description: "Initiates a socket connection"},
	Accept:         {Name: "accept", Category: Net, Description: "Accepts a socket connection"},
	Mmap:           {Name: "mmap", Category: Mem, Description: "Maps files or devices into memory"},
	ProcessVMRead:  {Name: "process_vm_readv", Category: Mem, Description: "Reads memory from another process"},
	ProcessVMWrite: {Name: "process_vm_writev", Category: Mem, Description: "Writes memory into another process"},
	Kill:           {Name: "kill", Category: Process, Description: "Sends a signal to a process"},
	Ptrace:         {Name: "ptrace", Category: Process, Description: "Traces or controls another process"},
	Prctl:          {Name: "prctl", Category: Process, Description: "Performs a process-control operation"},
}

var types = map[string]Type{
	"execve":            Execve,
	"exit":              Exit,
	"clone":             Clone,
	"openat":            Openat,
	"unlink":            Unlink,
	"rename":            Rename,
	"connect":           Connect,
	"accept":            Accept,
	"mmap":              Mmap,
	"process_vm_readv":  ProcessVMRead,
	"process_vm_writev": ProcessVMWrite,
	"kill":              Kill,
	"ptrace":            Ptrace,
	"prctl":             Prctl,
}

// All returns all Linux event types.
func All() []Type {
	return []Type{
		Execve, Exit, Clone,
		Openat, Unlink, Rename,
		Connect, Accept,
		Mmap, ProcessVMRead, ProcessVMWrite,
		Kill, Ptrace, Prctl,
	}
}

// MaxTypeID returns the largest Linux event type identifier.
func MaxTypeID() uint16 {
	return uint16(slices.Max(All()))
}

// TypeToEventInfo returns metadata for an event type.
func TypeToEventInfo(typ Type) Info {
	if info, ok := events[typ]; ok {
		return info
	}
	return Info{Name: "N/A", Category: Unknown}
}

// NameToType converts an event name to its type.
func NameToType(name string) Type {
	if typ, ok := types[name]; ok {
		return typ
	}
	return UnknownType
}

// NameToTypes converts an event name to its possible internal types.
func NameToTypes(name string) []Type {
	return []Type{NameToType(name)}
}
