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

// Parameter schemas. Every event starts with the common parameters, followed
// by the parameters specific to the syscall. The tail parameters are optional and
// they're appended by the consumer when the corresponding data is available.
var (
	commonParams = []ParamInfo{
		pi(params.ProcessID, params.PID),
		pi(params.ThreadID, params.TID),
		pi(params.ProcessParentID, params.PID),
		pi(params.ProcessName, params.String),
		pi(params.UID, params.Uint32),
		pi(params.GID, params.Uint32),
		pi(params.SyscallID, params.Uint32),
		pi(params.Retval, params.Int64),
		pi(params.StartBootTime, params.Uint64),
	}
	tailParams = []ParamInfo{
		pi(params.Exe, params.Path),
		pi(params.Cmdline, params.String),
		pi(params.Truncated, params.Uint32),
	}

	execveParams = slices.Concat(commonParams, tailParams)
	exitParams   = slices.Concat(commonParams, []ParamInfo{pi(params.ExitStatus, params.Int64)}, tailParams)
	cloneParams  = slices.Concat(commonParams, []ParamInfo{pi(params.CloneFlags, params.Uint64)}, tailParams)
	openatParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.DirFD, params.Int64),
		pi(params.FilePath, params.Path),
		pi(params.FileFlags, params.Uint64),
		pi(params.FileMode, params.Uint64),
		pi(params.FD, params.Int64),
	}, tailParams)
	unlinkParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.DirFD, params.Int64),
		pi(params.FilePath, params.Path),
		pi(params.FileFlags, params.Uint64),
	}, tailParams)
	renameParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.DirFD, params.Int64),
		pi(params.NewDirFD, params.Int64),
		pi(params.FilePath, params.Path),
		pi(params.FileNewPath, params.Path),
		pi(params.FileFlags, params.Uint64),
	}, tailParams)
	socketParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.FD, params.Int64),
		pi(params.NewFD, params.Int64),
		pi(params.SockFlags, params.Uint64),
		pi(params.SockFamily, params.Uint16),
		pi(params.SockPath, params.Path),
		pi(params.NetDIP, params.IP),
		pi(params.NetDport, params.Port),
		pi(params.NetSIP, params.IP),
		pi(params.NetSport, params.Port),
	}, tailParams)
	mmapParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.MemBaseAddress, params.Address),
		pi(params.MemRegionSize, params.Uint64),
		pi(params.MemProtect, params.Uint32),
		pi(params.MmapFlags, params.Uint64),
		pi(params.FD, params.Int64),
		pi(params.MmapOffset, params.Uint64),
	}, tailParams)
	processVMParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.TargetProcessID, params.Int64),
		pi(params.MemBaseAddress, params.Address),
		pi(params.MemRegionSize, params.Uint64),
		pi(params.MmapFlags, params.Uint64),
	}, tailParams)
	killParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.TargetProcessID, params.Int64),
		pi(params.Signal, params.Int32),
	}, tailParams)
	ptraceParams = slices.Concat(commonParams, []ParamInfo{
		pi(params.PtraceRequest, params.Int64),
		pi(params.TargetProcessID, params.Int64),
		pi(params.PtraceAddr, params.Address),
		pi(params.PtraceData, params.Uint64),
	}, tailParams)
	prctlParams = slices.Concat(commonParams, []ParamInfo{pi(params.PrctlOption, params.Int64)}, tailParams)
)

var table = [MaxEvent]Info{
	Execve:         {Name: "execve", Category: Process, Source: RawSyscallTracepoint, Description: "Executes a program", Params: execveParams},
	Exit:           {Name: "exit", Category: Process, Source: RawSyscallTracepoint, Description: "Exit all threads in a process", Params: exitParams},
	Clone:          {Name: "clone", Category: Process, Source: RawSyscallTracepoint, Description: "Creates a child process", Params: cloneParams},
	Openat:         {Name: "openat", Category: File, Source: RawSyscallTracepoint, Description: "Opens or creates a file", Params: openatParams},
	Unlink:         {Name: "unlink", Category: File, Source: RawSyscallTracepoint, Description: "Removes a directory entry", Params: unlinkParams},
	Rename:         {Name: "rename", Category: File, Source: RawSyscallTracepoint, Description: "Renames a file or directory", Params: renameParams},
	Connect:        {Name: "connect", Category: Network, Source: RawSyscallTracepoint, Description: "Initiates a socket connection", Params: socketParams},
	Accept:         {Name: "accept", Category: Network, Source: RawSyscallTracepoint, Description: "Accepts a socket connection", Params: socketParams},
	Mmap:           {Name: "mmap", Category: Memory, Source: RawSyscallTracepoint, Description: "Maps files or devices into memory", Params: mmapParams},
	ProcessVMRead:  {Name: "process_vm_read", Category: Memory, Source: RawSyscallTracepoint, Description: "Reads memory from another process", Params: processVMParams},
	ProcessVMWrite: {Name: "process_vm_write", Category: Memory, Source: RawSyscallTracepoint, Description: "Writes memory into another process", Params: processVMParams},
	Kill:           {Name: "kill", Category: Process, Source: RawSyscallTracepoint, Description: "Sends a signal to a process", Params: killParams},
	Ptrace:         {Name: "ptrace", Category: Process, Source: RawSyscallTracepoint, Description: "Traces or controls another process", Params: ptraceParams},
	Prctl:          {Name: "prctl", Category: Process, Source: RawSyscallTracepoint, Description: "Performs a process-control operation", Params: prctlParams},
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
