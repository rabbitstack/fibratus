/*
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

package params

import (
	"slices"
)

type ParamInfo struct {
	BaseParamInfo
}

// SyscallCommonDescriptor represents the common parameters descriptor.
var SyscallCommonDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID},
	{Name: ThreadID, Type: TID},
	{Name: ProcessParentID, Type: PID},
	{Name: ProcessName, Type: String},
	{Name: UID, Type: Uint32},
	{Name: GID, Type: Uint32},
	{Name: SyscallID, Type: Uint32},
	{Name: Retval, Type: Uint64},
	{Name: StartBootTime, Type: Uint64},
}

// Parameter schemas. Every event starts with the common parameters, followed
// by the parameters specific to the syscall.

var ExecveDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var ExitDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: ExitStatus, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var CloneDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: CloneFlags, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var OpenatDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: DirFD, Type: Int64},
		{Name: FilePath, Type: Path},
		{Name: FileFlags, Type: Uint64},
		{Name: FileMode, Type: Uint64},
		{Name: FD, Type: Int64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var UnlinkDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: DirFD, Type: Int64},
		{Name: FilePath, Type: Path},
		{Name: FileFlags, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var RenameDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: DirFD, Type: Int64},
		{Name: NewDirFD, Type: Int64},
		{Name: FilePath, Type: Path},
		{Name: FileNewPath, Type: Path},
		{Name: FileFlags, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var SocketDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: FD, Type: Int64},
		{Name: NewFD, Type: Int64},
		{Name: SockFlags, Type: Uint64},
		{Name: SockFamily, Type: Uint16},
		{Name: SockPath, Type: Path},
		{Name: NetDIP, Type: IP},
		{Name: NetDport, Type: Port},
		{Name: NetSIP, Type: IP},
		{Name: NetSport, Type: Port},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var MmapDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: MemBaseAddress, Type: Address},
		{Name: MemRegionSize, Type: Uint64},
		{Name: MemProtect, Type: Uint32},
		{Name: MmapFlags, Type: Uint64},
		{Name: FD, Type: Int64},
		{Name: MmapOffset, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var ProcessVMWriteDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: TargetProcessID, Type: Int64},
		{Name: MemBaseAddress, Type: Address},
		{Name: MemRegionSize, Type: Uint64},
		{Name: MmapFlags, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var ProcessVMReadDescriptor = ProcessVMWriteDescriptor

var KillDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: TargetProcessID, Type: Int64},
		{Name: Signal, Type: Int32},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var PtraceDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: PtraceRequest, Type: Int64},
		{Name: TargetProcessID, Type: Int64},
		{Name: PtraceAddr, Type: Address},
		{Name: PtraceData, Type: Uint64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)

var PrctlDescriptor = slices.Concat(
	SyscallCommonDescriptor,
	[]ParamInfo{
		{Name: PrctlOption, Type: Int64},
		{Name: Exe, Type: Path},
		{Name: Cmdline, Type: String},
	},
)
