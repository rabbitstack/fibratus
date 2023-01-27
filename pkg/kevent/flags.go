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
	Value uint32
}

func (f ParamFlag) eval(v uint32) bool {
	return (v == 0 && f.Value == 0) || (f.Value != 0 && (v&f.Value) == f.Value && v != 0)
}

// ParamFlags represents the type alias for the event parameter flags
type ParamFlags []ParamFlag

// String produces a string with all flags present in the bitmask and delimited
// with the `|` separator.
func (flags ParamFlags) String(f uint32) string {
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
