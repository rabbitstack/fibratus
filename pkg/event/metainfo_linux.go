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

	"github.com/rabbitstack/fibratus/pkg/event/params"
)

var table = [MaxEvent]Info{
	Execve:         {Name: "execve", Category: Process, Source: RawSyscallTracepoint, Description: "Executes a program", Params: params.ExecveDescriptor},
	Exit:           {Name: "exit", Category: Process, Source: RawSyscallTracepoint, Description: "Exit all threads in a process", Params: params.ExitDescriptor},
	Clone:          {Name: "clone", Category: Process, Source: RawSyscallTracepoint, Description: "Creates a child process", Params: params.CloneDescriptor},
	Openat:         {Name: "openat", Category: File, Source: RawSyscallTracepoint, Description: "Opens or creates a file", Params: params.OpenatDescriptor},
	Unlink:         {Name: "unlink", Category: File, Source: RawSyscallTracepoint, Description: "Removes a directory entry", Params: params.UnlinkDescriptor},
	Rename:         {Name: "rename", Category: File, Source: RawSyscallTracepoint, Description: "Renames a file or directory", Params: params.RenameDescriptor},
	Connect:        {Name: "connect", Category: Network, Source: RawSyscallTracepoint, Description: "Initiates a socket connection", Params: params.SocketDescriptor},
	Accept:         {Name: "accept", Category: Network, Source: RawSyscallTracepoint, Description: "Accepts a socket connection", Params: params.SocketDescriptor},
	Mmap:           {Name: "mmap", Category: Memory, Source: RawSyscallTracepoint, Description: "Maps files or devices into memory", Params: params.MmapDescriptor},
	ProcessVMRead:  {Name: "process_vm_read", Category: Memory, Source: RawSyscallTracepoint, Description: "Reads memory from another process", Params: params.ProcessVMReadDescriptor},
	ProcessVMWrite: {Name: "process_vm_write", Category: Memory, Source: RawSyscallTracepoint, Description: "Writes memory into another process", Params: params.ProcessVMWriteDescriptor},
	Kill:           {Name: "kill", Category: Process, Source: RawSyscallTracepoint, Description: "Sends a signal to a process", Params: params.KillDescriptor},
	Ptrace:         {Name: "ptrace", Category: Process, Source: RawSyscallTracepoint, Description: "Traces or controls another process", Params: params.PtraceDescriptor},
	Prctl:          {Name: "prctl", Category: Process, Source: RawSyscallTracepoint, Description: "Performs a process-control operation", Params: params.PrctlDescriptor},
}

// GetTypesInfo returns event types metadata.
func GetTypesInfo() []Info {
	// work on a copy, otherwise the in-place deletion and sorting
	// would corrupt the table which is indexed by the event type
	t := slices.Clone(table[:])
	t = slices.DeleteFunc(t, func(info Info) bool {
		return info.Name == ""
	})
	slices.SortFunc(t, func(a, b Info) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return t
}
