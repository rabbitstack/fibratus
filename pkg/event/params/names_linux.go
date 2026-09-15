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

package params

const (
	// CloneFlags is the bitmask supplied to clone(2).
	CloneFlags = "clone_flags"
	// UID is the effective Linux user identifier.
	UID = "uid"
	// GID is the effective Linux group identifier.
	GID = "gid"
	// SyscallID is the raw architecture-specific syscall number.
	SyscallID = "syscall_id"
	// Retval is the syscall return value.
	Retval = "retval"
	// StartBootTime is the process start time measured from system boot, in nanoseconds.
	StartBootTime = "start_boot_time"
	// DirFD is a directory file descriptor, including AT_FDCWD.
	DirFD = "dirfd"
	// NewDirFD is the destination directory file descriptor for renameat.
	NewDirFD = "new_dirfd"
	// FileNewPath is the destination path of a rename.
	FileNewPath = "file_new_path"
	// FileFlags is the raw openat, unlinkat, or renameat2 flags bitmask.
	FileFlags = "file_flags"
	// FileMode is the file creation mode supplied to openat.
	FileMode = "file_mode"
	// FD is a file descriptor.
	FD = "fd"
	// SockFamily is the socket address family (AF_INET, AF_INET6, AF_UNIX).
	SockFamily = "sock_family"
	// SockPath is the filesystem path of an AF_UNIX socket.
	SockPath = "sock_path"
	// MmapFlags is the raw mmap flags bitmask.
	MmapFlags = "mmap_flags"
	// MmapOffset is the file offset of a memory mapping.
	MmapOffset = "mmap_offset"
	// Signal is a POSIX signal number.
	Signal = "signal"
	// PtraceRequest is the ptrace request code.
	PtraceRequest = "ptrace_request"
	// PtraceAddr is the ptrace address argument.
	PtraceAddr = "ptrace_addr"
	// PtraceData is the ptrace data argument.
	PtraceData = "ptrace_data"
	// PrctlOption is the prctl option code.
	PrctlOption = "prctl_option"
	// Truncated is a bitmask of truncated variable-length fields.
	Truncated = "truncated"
)
