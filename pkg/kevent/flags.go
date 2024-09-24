/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package kevent

import (
	"golang.org/x/sys/windows"
	"strings"
)

// ParamFlag defines the mapping between the flag value and its symbolical name.
type ParamFlag struct {
	Name  string
	Value uint64
}

func (f ParamFlag) eval(v uint64) bool {
	return (v == 0 && f.Value == 0) || (f.Value != 0 && (v&f.Value) == f.Value && v != 0)
}

// ParamFlags represents the type alias for the event parameter flags
type ParamFlags []ParamFlag

// String produces a string with all flags present in the bitmask and delimited
// with the `|` separator.
func (flags ParamFlags) String(f uint64) string {
	var (
		n strings.Builder
		s string
	)
	for _, flag := range flags {
		if flag.eval(f) {
			n.WriteString(s)
			n.WriteString(flag.Name)
			s = "|"
			// remove current flags value to avoid duplicates
			f &= ^flag.Value
		}
	}
	return n.String()
}

const (
	// PsApplicationID identifies the packaged process
	PsApplicationID = 0x00000001
	// PsWOW64 indicates if the 32-bit process is created in 64-bit Windows system
	PsWOW64 = 0x00000002
	// PsProtected process is to be run as a protected process. The system restricts
	// access to protected processes and the threads of protected processes.
	PsProtected = 0x00000004
	// PsPackaged represents a process packaged with the MSIX technology and thus has
	// package identity.
	PsPackaged = 0x00000008
)

// PsCreationFlags describes the process creation flags.
var PsCreationFlags = []ParamFlag{
	{"APPLICATION_ID", PsApplicationID},
	{"WOW64", PsWOW64},
	{"PROTECTED", PsProtected},
	{"PACKAGED", PsPackaged},
}

// PsAccessRightFlags describes flags for the process access rights.
var PsAccessRightFlags = []ParamFlag{
	{"ALL_ACCESS", windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF},
	{"DELETE", windows.DELETE},
	{"READ_CONTROL", windows.READ_CONTROL},
	{"SYNCHRONIZE", windows.SYNCHRONIZE},
	{"WRITE_DAC", windows.WRITE_DAC},
	{"WRITE_OWNER", windows.WRITE_OWNER},
	{"GENERIC_READ", windows.GENERIC_READ},
	{"ACCESS_SYSTEM_SECURITY", windows.ACCESS_SYSTEM_SECURITY},
	{"TERMINATE", windows.PROCESS_TERMINATE},
	{"CREATE_THREAD", windows.PROCESS_CREATE_THREAD},
	{"VM_OPERATION", windows.PROCESS_VM_OPERATION},
	{"VM_READ", windows.PROCESS_VM_READ},
	{"VM_WRITE", windows.PROCESS_VM_WRITE},
	{"DUP_HANDLE", windows.PROCESS_DUP_HANDLE},
	{"CREATE_PROCESS", windows.PROCESS_CREATE_PROCESS},
	{"SET_QUOTA", windows.PROCESS_SET_QUOTA},
	{"SET_INFORMATION", windows.PROCESS_SET_INFORMATION},
	{"QUERY_INFORMATION", windows.PROCESS_QUERY_INFORMATION},
	{"SUSPEND_RESUME", windows.PROCESS_SUSPEND_RESUME},
	{"QUERY_LIMITED_INFORMATION", windows.PROCESS_QUERY_LIMITED_INFORMATION},
}

// ThreadAccessRightFlags describes flags for the thread access rights.
var ThreadAccessRightFlags = []ParamFlag{
	{"ALL_ACCESS", windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF},
	{"DELETE", windows.DELETE},
	{"READ_CONTROL", windows.READ_CONTROL},
	{"SYNCHRONIZE", windows.SYNCHRONIZE},
	{"WRITE_DAC", windows.WRITE_DAC},
	{"WRITE_OWNER", windows.WRITE_OWNER},
	{"TERMINATE", windows.THREAD_TERMINATE},
	{"SUSPEND_THREAD", windows.THREAD_SUSPEND_RESUME},
	{"GET_CONTEXT", windows.THREAD_GET_CONTEXT},
	{"SET_CONTEXT", windows.THREAD_SET_CONTEXT},
	{"SET_INFORMATION", windows.THREAD_SET_INFORMATION},
	{"QUERY_INFORMATION", windows.THREAD_QUERY_INFORMATION},
	{"SET_THREAD_TOKEN", windows.THREAD_SET_THREAD_TOKEN},
	{"IMPERSONATE", windows.THREAD_IMPERSONATE},
	{"DIRECT_IMPERSONATION", windows.THREAD_DIRECT_IMPERSONATION},
	{"SET_LIMITED_INFORMATION", windows.THREAD_SET_LIMITED_INFORMATION},
	{"QUERY_LIMITED_INFORMATION", windows.THREAD_QUERY_LIMITED_INFORMATION},
}

// FileAttributeFlags describes file attribute flags.
var FileAttributeFlags = []ParamFlag{
	{"READ_ONLY", windows.FILE_ATTRIBUTE_READONLY},
	{"HIDDEN", windows.FILE_ATTRIBUTE_HIDDEN},
	{"SYSTEM", windows.FILE_ATTRIBUTE_SYSTEM},
	{"DIRECTORY", windows.FILE_ATTRIBUTE_DIRECTORY},
	{"ARCHIVE", windows.FILE_ATTRIBUTE_ARCHIVE},
	{"DEVICE", windows.FILE_ATTRIBUTE_DEVICE},
	{"NORMAL", windows.FILE_ATTRIBUTE_NORMAL},
	{"TEMPORARY", windows.FILE_ATTRIBUTE_TEMPORARY},
	{"SPARSE", windows.FILE_ATTRIBUTE_SPARSE_FILE},
	{"JUNCTION", windows.FILE_ATTRIBUTE_REPARSE_POINT},
	{"COMPRESSED", windows.FILE_ATTRIBUTE_COMPRESSED},
	{"OFFLINE", windows.FILE_ATTRIBUTE_OFFLINE},
	{"UNINDEXED", windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED},
	{"ENCRYPTED", windows.FILE_ATTRIBUTE_ENCRYPTED},
	{"STREAM", windows.FILE_ATTRIBUTE_INTEGRITY_STREAM},
	{"VIRTUAL", windows.FILE_ATTRIBUTE_VIRTUAL},
	{"NO_SCRUB", windows.FILE_ATTRIBUTE_NO_SCRUB_DATA},
	{"RECALL_OPEN", windows.FILE_ATTRIBUTE_RECALL_ON_OPEN},
	{"RECALL_ACCESS", windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS},
	{"PINNED", 0x80000},
	{"UNPINNED", 0x100000},
}

// FileCreateOptionsFlags describes file create options flags
var FileCreateOptionsFlags = []ParamFlag{
	{"DIRECTORY_FILE", windows.FILE_DIRECTORY_FILE},
	{"WRITE_THROUGH", windows.FILE_WRITE_THROUGH},
	{"SEQUENTIAL_ONLY", windows.FILE_SEQUENTIAL_ONLY},
	{"NO_INTERMEDIATE_BUFFERING", windows.FILE_NO_INTERMEDIATE_BUFFERING},
	{"SYNCHRONOUS_IO_ALERT", windows.FILE_SYNCHRONOUS_IO_ALERT},
	{"SYNCHRONOUS_IO_NONALERT", windows.FILE_SYNCHRONOUS_IO_NONALERT},
	{"NON_DIRECTORY_FILE", windows.FILE_NON_DIRECTORY_FILE},
	{"CREATE_TREE_CONNECTION", windows.FILE_CREATE_TREE_CONNECTION},
	{"COMPLETE_IF_OPLOCKED", windows.FILE_COMPLETE_IF_OPLOCKED},
	{"NO_EA_KNOWLEDGE", windows.FILE_NO_EA_KNOWLEDGE},
	{"OPEN_REMOTE_INSTANCE", windows.FILE_OPEN_REMOTE_INSTANCE},
	{"RANDOM_ACCESS", windows.FILE_RANDOM_ACCESS},
	{"DELETE_ON_CLOSE", windows.FILE_DELETE_ON_CLOSE},
	{"OPEN_BY_FILE_ID", windows.FILE_OPEN_BY_FILE_ID},
	{"FOR_BACKUP_INTENT", windows.FILE_OPEN_FOR_BACKUP_INTENT},
	{"NO_COMPRESSION", windows.FILE_NO_COMPRESSION},
	{"OPEN_REQUIRING_OPLOCK", windows.FILE_OPEN_REQUIRING_OPLOCK},
	{"DISALLOW_EXCLUSIVE", windows.FILE_DISALLOW_EXCLUSIVE},
	{"RESERVE_OPFILTER", windows.FILE_RESERVE_OPFILTER},
	{"OPEN_REPARSE_POINT", windows.FILE_OPEN_REPARSE_POINT},
	{"OPEN_NO_RECALL", windows.FILE_OPEN_NO_RECALL},
	{"OPEN_FOR_FREE_SPACE_QUERY", windows.FILE_OPEN_FOR_FREE_SPACE_QUERY},
}

// FileShareModeFlags describes file share mask flags
var FileShareModeFlags = []ParamFlag{
	{"READ", windows.FILE_SHARE_READ},
	{"WRITE", windows.FILE_SHARE_WRITE},
	{"DELETE", windows.FILE_SHARE_DELETE},
}

// MemAllocationFlags describes virtual allocation/free type flags
var MemAllocationFlags = []ParamFlag{
	{"COMMIT", windows.MEM_COMMIT},
	{"RESERVE", windows.MEM_RESERVE},
	{"RESET", windows.MEM_RESET},
	{"RESET_UNDO", windows.MEM_RESET_UNDO},
	{"PHYSICAL", windows.MEM_PHYSICAL},
	{"LARGE_PAGES", windows.MEM_LARGE_PAGES},
	{"TOP_DOWN", windows.MEM_TOP_DOWN},
	{"RELEASE", windows.MEM_RELEASE},
	{"DECOMMIT", windows.MEM_DECOMMIT},
	{"WRITE_WATCH", windows.MEM_WRITE_WATCH},
}

// MemProtectionFlags represents memory protection option flags.
var MemProtectionFlags = []ParamFlag{
	{"NONE", 0},
	{"EXECUTE", windows.PAGE_EXECUTE},
	{"EXECUTE_READ", windows.PAGE_EXECUTE_READ},
	{"EXECUTE_READWRITE", windows.PAGE_EXECUTE_READWRITE},
	{"EXECUTE_WRITECOPY", windows.PAGE_EXECUTE_WRITECOPY},
	{"NOACCESS", windows.PAGE_NOACCESS},
	{"READONLY", windows.PAGE_READONLY},
	{"READWRITE", windows.PAGE_READWRITE},
	{"WRITECOPY", windows.PAGE_WRITECOPY},
	{"TARGETS_INVALID", windows.PAGE_TARGETS_INVALID},
	{"TARGETS_NO_UPDATE", windows.PAGE_TARGETS_NO_UPDATE},
	{"GUARD", windows.PAGE_GUARD},
	{"NOCACHE", windows.PAGE_NOCACHE},
	{"WRITECOMBINE", windows.PAGE_WRITECOMBINE},
}

// ViewProtectionFlags describes section protection flags. These
// have different values than the memory protection flags as they
// are reported by the kernel.
var ViewProtectionFlags = []ParamFlag{
	{"EXECUTE_READWRITE", 0x60000},
	{"EXECUTE_WRITECOPY", 0x70000},
	{"NOCACHE", 0x80000},
	{"WRITECOMBINE", 0x90000},
	{"READONLY", 0x10000},
	{"EXECUTE", 0x20000},
	{"EXECUTE_READ", 0x30000},
	{"READWRITE", 0x40000},
	{"WRITECOPY", 0x50000},
}

// DNSOptsFlags describes DNS query/response options.
var DNSOptsFlags = []ParamFlag{
	{"STANDARD", 0x00000000},
	{"ACCEPT_TRUNCATED_RESPONSE", 0x00000001},
	{"USE_TCP_ONLY", 0x00000002},
	{"NO_RECURSION", 0x00000004},
	{"BYPASS_CACHE", 0x00000008},
	{"NO_WIRE_QUERY", 0x00000010},
	{"NO_LOCAL_NAME", 0x00000020},
	{"NO_NETBT", 0x00000080},
	{"WIRE_ONLY", 0x00000100},
	{"RETURN_MESSAGE", 0x00000200},
	{"MULTICAST_ONLY", 0x00000400},
	{"NO_MULTICAST", 0x00000800},
	{"TREAT_AS_FQDN", 0x00001000},
	{"ADDRCONFIG", 0x00002000},
	{"DUAL_ADDR", 0x00004000},
	{"MULTICAST_WAIT", 0x00020000},
	{"MULTICAST_VERIFY", 0x00040000},
	{"DONT_RESET_TTL_VALUES", 0x00100000},
	{"DISABLE_IDN_ENCODING", 0x00200000},
	{"APPEND_MULTILABEL", 0x00800000},
}
