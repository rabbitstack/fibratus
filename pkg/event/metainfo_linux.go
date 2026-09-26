//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * Copyright 2026 by Nedim Sabic Sabic
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

var table = [MaxEvent]Info{
	Execve:         {Name: "execve", Category: Process, Source: RawSyscallTracepoint, Description: "Executes a program"},
	Exit:           {Name: "exit", Category: Process, Source: RawSyscallTracepoint, Description: "Exit all threads in a process"},
	Openat:         {Name: "openat", Category: File, Source: RawSyscallTracepoint, Description: "Opens or creates a file"},
	Unlink:         {Name: "unlink", Category: File, Source: RawSyscallTracepoint, Description: "Removes a directory entry"},
	Rename:         {Name: "rename", Category: File, Source: RawSyscallTracepoint, Description: "Renames a file or directory"},
	Connect:        {Name: "connect", Category: Network, Source: RawSyscallTracepoint, Description: "Initiates a socket connection"},
	Accept:         {Name: "accept", Category: Network, Source: RawSyscallTracepoint, Description: "Accepts a socket connection"},
	Mmap:           {Name: "mmap", Category: Memory, Source: RawSyscallTracepoint, Description: "Maps files or devices into memory"},
	ProcessVMRead:  {Name: "process_vm_read", Category: Memory, Source: RawSyscallTracepoint, Description: "Reads memory from another process"},
	ProcessVMWrite: {Name: "process_vm_write", Category: Memory, Source: RawSyscallTracepoint, Description: "Writes memory into another process"},
	Kill:           {Name: "kill", Category: Process, Source: RawSyscallTracepoint, Description: "Sends a signal to a process"},
	Ptrace:         {Name: "ptrace", Category: Process, Source: RawSyscallTracepoint, Description: "Traces or controls another process"},
	Prctl:          {Name: "prctl", Category: Process, Source: RawSyscallTracepoint, Description: "Performs a process-control operation"},
}

// GetTypesInfo returns event types metadata.
func GetTypesInfo() []Info {
	t := table[:]
	t = slices.DeleteFunc(t, func(info Info) bool {
		return info.Name == ""
	})
	slices.SortFunc(t, func(a, b Info) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return t
}
