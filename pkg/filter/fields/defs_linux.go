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

func platformString() params.Type     { return params.String }
func platformAnsiString() params.Type { return params.String }

var fields = platformFields(map[Field]FieldInfo{
	EvtPID:           {EvtPID, "process identifier generating the event", params.Uint64, []string{"evt.pid = 6"}, nil, nil},
	EvtTID:           {EvtTID, "thread identifier generating the event", params.Uint64, []string{"evt.tid = 1024"}, nil, nil},
	EvtRetval:        {EvtRetval, "syscall return value", params.Int64, []string{"evt.retval < 0"}, nil, nil},
	EvtSyscall:       {EvtSyscall, "raw architecture-specific syscall number", params.Uint32, []string{"evt.syscall = 59"}, nil, nil},
	EvtTruncated:     {EvtTruncated, "indicates whether variable-length event fields were truncated", params.Bool, []string{"evt.truncated = true"}, nil, nil},
	PsPid:            {PsPid, "process identifier", params.Uint64, []string{"ps.pid = 1024"}, nil, nil},
	PsPpid:           {PsPpid, "parent process identifier", params.Uint64, []string{"ps.ppid = 45"}, nil, nil},
	PsParentPid:      {PsParentPid, "parent process id", params.Uint64, []string{"ps.parent.pid = 4"}, nil, nil},
	PsUUID:           {PsUUID, "unique process identifier", params.Uint64, []string{"ps.uuid > 6000054355"}, nil, nil},
	PsParentUUID:     {PsParentUUID, "unique parent process identifier", params.Uint64, []string{"ps.parent.uuid > 6000054355"}, nil, nil},
	PsUID:            {PsUID, "real user identifier of the process", params.Uint32, []string{"ps.uid = 0"}, nil, nil},
	PsGID:            {PsGID, "real group identifier of the process", params.Uint32, []string{"ps.gid = 0"}, nil, nil},
	PsParentArgs:     {PsParentArgs, "parent process command line arguments", params.Slice, []string{"ps.parent.args in ('-c', 'bash')"}, nil, nil},
	PsParentCwd:      {PsParentCwd, "parent process current working directory", platformString(), []string{"ps.parent.cwd = '/home/user'"}, nil, nil},
	PsParentUsername: {PsParentUsername, "parent process username", platformString(), []string{"ps.parent.username = 'root'"}, nil, nil},
	PsParentEnvs:     {PsParentEnvs, "parent process environment variables", params.Slice, []string{"ps.parent.envs in ('PATH:/usr/bin')"}, nil, nil},
	PsSignal:         {PsSignal, "POSIX signal number", params.Int64, []string{"ps.signal = 9"}, nil, nil},
	PsTargetPID:      {PsTargetPID, "target process identifier of kill, ptrace, or process_vm operations", params.Uint64, []string{"ps.target.pid = 4242"}, nil, nil},
	PsPtraceRequest:  {PsPtraceRequest, "ptrace request code", params.Int64, []string{"ps.ptrace.request = 16"}, nil, nil},
	PsPrctlOption:    {PsPrctlOption, "prctl option code", params.Int64, []string{"ps.prctl.option = 15"}, nil, nil},
	PsCloneFlags:     {PsCloneFlags, "clone flags bitmask", params.Uint64, []string{"ps.clone.flags = 0"}, nil, nil},
	FilePath:         {FilePath, "full file path", platformString(), []string{"file.path = '/etc/passwd'"}, nil, nil},
	FilePathStem:     {FilePathStem, "full file path without extension", platformString(), []string{"file.path.stem = '/tmp/secret'"}, nil, nil},
	FileName:         {FileName, "file base name", platformString(), []string{"file.name = 'passwd'"}, nil, nil},
	FileExtension:    {FileExtension, "file extension", platformAnsiString(), []string{"file.extension = '.so'"}, nil, nil},
	FileNewPath:      {FileNewPath, "destination path of a rename", platformString(), []string{"file.new_path = '/tmp/renamed'"}, nil, nil},
	FileDirFD:        {FileDirFD, "directory file descriptor, including AT_FDCWD", params.Int64, []string{"file.dirfd < 0"}, nil, nil},
	FileFD:           {FileFD, "file descriptor returned by openat", params.Int64, []string{"file.fd = 3"}, nil, nil},
	FileFlags:        {FileFlags, "raw openat, unlinkat, or renameat flags bitmask", params.Uint64, []string{"file.flags = 0"}, nil, nil},
	FileMode:         {FileMode, "file creation mode supplied to openat", params.Uint64, []string{"file.mode = 420"}, nil, nil},
	FileTruncated:    {FileTruncated, "indicates whether the file path was truncated", params.Bool, []string{"file.truncated = true"}, nil, nil},
	NetDIP:           {NetDIP, "destination IP address", params.IP, []string{"net.dip = 172.17.0.3"}, nil, nil},
	NetSIP:           {NetSIP, "source IP address", params.IP, []string{"net.sip = 127.0.0.1"}, nil, nil},
	NetDport:         {NetDport, "destination port", params.Uint16, []string{"net.dport in (80, 443, 8080)"}, nil, nil},
	NetSport:         {NetSport, "source port", params.Uint16, []string{"net.sport != 3306"}, nil, nil},
	NetFamily:        {NetFamily, "socket address family", params.Uint16, []string{"net.family = 2"}, nil, nil},
	NetPath:          {NetPath, "filesystem path of an AF_UNIX socket", platformString(), []string{"net.path = '/tmp/app.sock'"}, nil, nil},
	NetFD:            {NetFD, "socket file descriptor", params.Int64, []string{"net.fd = 5"}, nil, nil},
	MemBaseAddress:   {MemBaseAddress, "region base address", params.Uint64, []string{"mem.address = 8192"}, nil, nil},
	MemRegionSize:    {MemRegionSize, "region size", params.Uint64, []string{"mem.size > 4096"}, nil, nil},
	MemProtection:    {MemProtection, "mapping protection bitmask", params.Uint32, []string{"mem.protection = 3"}, nil, nil},
	MemFlags:         {MemFlags, "mmap flags bitmask", params.Uint64, []string{"mem.flags = 1"}, nil, nil},
	MemFD:            {MemFD, "file descriptor backing a mapping", params.Int64, []string{"mem.fd = 3"}, nil, nil},
	MemOffset:        {MemOffset, "file offset of a memory mapping", params.Uint64, []string{"mem.offset = 0"}, nil, nil},
	MemTargetPID:     {MemTargetPID, "target process identifier of a process_vm operation", params.Uint64, []string{"mem.target.pid = 4242"}, nil, nil},
	ThreadTID:        {ThreadTID, "thread identifier", params.Uint64, []string{"thread.tid = 1024"}, nil, nil},
	ThreadPID:        {ThreadPID, "thread group identifier of the thread", params.Uint64, []string{"thread.pid = 1024"}, nil, nil},
})
