//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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

package fields

import "github.com/rabbitstack/fibratus/pkg/event/params"

func init() {
	fields[EvtRetval] = FieldInfo{EvtRetval, "syscall return value", params.Int64, []string{"evt.retval < 0"}, nil, nil}
	fields[EvtSyscallID] = FieldInfo{EvtSyscallID, "raw architecture-specific syscall number", params.Uint32, []string{"evt.syscall_id = 59"}, nil, nil}
	fields[PsPid] = FieldInfo{PsPid, "process identifier", params.Uint64, []string{"ps.pid = 1024"}, nil, nil}
	fields[PsPpid] = FieldInfo{PsPpid, "parent process identifier", params.Uint64, []string{"ps.ppid = 45"}, nil, nil}
	fields[PsParentPid] = FieldInfo{PsParentPid, "parent process id", params.Uint64, []string{"ps.parent.pid = 4"}, nil, nil}
	fields[PsUUID] = FieldInfo{PsUUID, "unique process identifier", params.Uint64, []string{"ps.uuid > 6000054355"}, nil, nil}
	fields[PsParentUUID] = FieldInfo{PsParentUUID, "unique parent process identifier", params.Uint64, []string{"ps.parent.uuid > 6000054355"}, nil, nil}
	fields[PsUID] = FieldInfo{PsUID, "real user identifier of the process", params.Uint32, []string{"ps.uid = 0"}, nil, nil}
	fields[PsGID] = FieldInfo{PsGID, "real group identifier of the process", params.Uint32, []string{"ps.gid = 0"}, nil, nil}
	fields[PsParentArgs] = FieldInfo{PsParentArgs, "parent process command line arguments", params.Slice, []string{"ps.parent.args in ('-c', 'bash')"}, nil, nil}
	fields[PsParentCwd] = FieldInfo{PsParentCwd, "parent process current working directory", params.String, []string{"ps.parent.cwd = '/home/user'"}, nil, nil}
	fields[PsParentUsername] = FieldInfo{PsParentUsername, "parent process username", params.String, []string{"ps.parent.username = 'root'"}, nil, nil}
	fields[PsParentEnvs] = FieldInfo{PsParentEnvs, "parent process environment variables", params.Slice, []string{"ps.parent.envs in ('PATH:/usr/bin')"}, nil, nil}
	fields[PsSignal] = FieldInfo{PsSignal, "POSIX signal number", params.Int64, []string{"ps.signal = 9"}, nil, nil}
	fields[PsTargetPID] = FieldInfo{PsTargetPID, "target process identifier of kill, ptrace, or process_vm operations. Signal targets keep the pid_t sign, where zero is the caller process group, -1 is every permitted process, and any other negative value is the process group of its absolute value", params.Int64, []string{"ps.target.pid = 4242", "ps.target.pid < 0"}, nil, nil}
	fields[PsPtraceRequest] = FieldInfo{PsPtraceRequest, "ptrace request code", params.Int64, []string{"ps.ptrace.request = 16"}, nil, nil}
	fields[PsPrctlOption] = FieldInfo{PsPrctlOption, "prctl option code", params.Int64, []string{"ps.prctl.option = 15"}, nil, nil}
	fields[PsCloneFlags] = FieldInfo{PsCloneFlags, "clone flags bitmask", params.Uint64, []string{"ps.clone_flags = 0"}, nil, nil}
	fields[FilePath] = FieldInfo{FilePath, "full file path", params.String, []string{"file.path = '/etc/passwd'"}, nil, nil}
	fields[FilePathStem] = FieldInfo{FilePathStem, "full file path without extension", params.String, []string{"file.path.stem = '/tmp/secret'"}, nil, nil}
	fields[FileName] = FieldInfo{FileName, "file base name", params.String, []string{"file.name = 'passwd'"}, nil, nil}
	fields[FileExtension] = FieldInfo{FileExtension, "file extension", params.String, []string{"file.extension = '.so'"}, nil, nil}
	fields[FilePathTarget] = FieldInfo{FilePathTarget, "destination path of a rename or similar source/target file operation", params.String, []string{"file.path.target = '/tmp/renamed'"}, nil, nil}
	fields[FileDirFD] = FieldInfo{FileDirFD, "directory file descriptor, including AT_FDCWD", params.Int64, []string{"file.dirfd < 0"}, nil, nil}
	fields[FileFD] = FieldInfo{FileFD, "file descriptor returned by openat", params.Int64, []string{"file.fd = 3"}, nil, nil}
	fields[FileFlags] = FieldInfo{FileFlags, "raw openat, unlinkat, or renameat flags bitmask", params.Uint64, []string{"file.flags = 0"}, nil, nil}
	fields[FileMode] = FieldInfo{FileMode, "file creation mode supplied to openat", params.Uint64, []string{"file.mode = 420"}, nil, nil}
	fields[NetDIP] = FieldInfo{NetDIP, "destination IP address", params.IP, []string{"net.dip = 172.17.0.3"}, nil, nil}
	fields[NetSIP] = FieldInfo{NetSIP, "source IP address", params.IP, []string{"net.sip = 127.0.0.1"}, nil, nil}
	fields[NetDport] = FieldInfo{NetDport, "destination port", params.Uint16, []string{"net.dport in (80, 443, 8080)"}, nil, nil}
	fields[NetSport] = FieldInfo{NetSport, "source port", params.Uint16, []string{"net.sport != 3306"}, nil, nil}
	fields[NetFamily] = FieldInfo{NetFamily, "socket address family", params.Uint16, []string{"net.family = 2"}, nil, nil}
	fields[NetUnixPath] = FieldInfo{NetUnixPath, "filesystem path of an AF_UNIX socket", params.String, []string{"net.unix_path = '/tmp/app.sock'"}, nil, nil}
	fields[NetFD] = FieldInfo{NetFD, "socket file descriptor", params.Int64, []string{"net.fd = 5"}, nil, nil}
	fields[MemBaseAddress] = FieldInfo{MemBaseAddress, "region base address", params.Uint64, []string{"mem.address = 8192"}, nil, nil}
	fields[MemRegionSize] = FieldInfo{MemRegionSize, "region size", params.Uint64, []string{"mem.size > 4096"}, nil, nil}
	fields[MemProtection] = FieldInfo{MemProtection, "mapping protection bitmask", params.Uint32, []string{"mem.protection = 3"}, nil, nil}
	fields[MemMmapFlags] = FieldInfo{MemMmapFlags, "mmap flags bitmask", params.Uint64, []string{"mem.mmap.flags = 1"}, nil, nil}
	fields[MemMmapFD] = FieldInfo{MemMmapFD, "file descriptor backing a mapping", params.Int64, []string{"mem.mmap.fd = 3"}, nil, nil}
	fields[MemMmapOffset] = FieldInfo{MemMmapOffset, "file offset of a memory mapping", params.Uint64, []string{"mem.mmap.offset = 0"}, nil, nil}
	fields[MemTargetPID] = FieldInfo{MemTargetPID, "target process identifier of a process_vm operation", params.Int64, []string{"mem.target.pid = 4242"}, nil, nil}
	fields[ThreadTID] = FieldInfo{ThreadTID, "thread identifier", params.Uint64, []string{"thread.tid = 1024"}, nil, nil}
	fields[ThreadPID] = FieldInfo{ThreadPID, "thread group identifier of the thread", params.Uint64, []string{"thread.pid = 1024"}, nil, nil}
}
