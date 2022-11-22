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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"golang.org/x/sys/windows"
	"strings"
)

// ParamFlag defines the mapping between the flag value and its symbolical name.
type ParamFlag struct {
	Name  string
	Value uint32
}

// ParamFlags represents the type alias for the event parameter flags
type ParamFlags []ParamFlag

// String produces a string with all flags present in the bitmask and delimited
// with the `|` separator.
func (flags ParamFlags) String(f uint32) string {
	var (
		sb  strings.Builder
		sep string
	)
	for _, flag := range flags {
		if (f == 0 && flag.Value == 0) || (flag.Value != 0 && (f&flag.Value) == flag.Value && f != 0) {
			sb.WriteString(sep)
			sb.WriteString(flag.Name)
			sep = "|"
			// remove current flags value to avoid duplicates
			f &= ^flag.Value
		}
	}
	return sb.String()
}

// PsAccessRightFlags describes flags for the process access rights.
var PsAccessRightFlags = []ParamFlag{
	{"ALL_ACCESS", uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF)},
	{"TERMINATE", uint32(windows.PROCESS_TERMINATE)},
	{"CREATE_THREAD", uint32(windows.PROCESS_CREATE_THREAD)},
	{"VM_OPERATION", uint32(windows.PROCESS_VM_OPERATION)},
	{"VM_READ", uint32(windows.PROCESS_VM_READ)},
	{"VM_WRITE", uint32(windows.PROCESS_VM_WRITE)},
	{"DUP_HANDLE", uint32(windows.PROCESS_DUP_HANDLE)},
	{"CREATE_PROCESS", uint32(windows.PROCESS_CREATE_PROCESS)},
	{"SET_QUOTA", uint32(windows.PROCESS_SET_QUOTA)},
	{"SET_INFORMATION", uint32(windows.PROCESS_SET_INFORMATION)},
	{"QUERY_INFORMATION", uint32(windows.PROCESS_QUERY_INFORMATION)},
	{"SUSPEND_RESUME", uint32(windows.PROCESS_SUSPEND_RESUME)},
	{"QUERY_LIMITED_INFORMATION", uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION)},
}

// ThreadAccessRightFlags describes flags for the thread access rights.
var ThreadAccessRightFlags = []ParamFlag{
	{"ALL_ACCESS", uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF)},
	{"TERMINATE", uint32(windows.THREAD_TERMINATE)},
	{"SUSPEND_THREAD", uint32(windows.THREAD_SUSPEND_RESUME)},
	{"GET_CONTEXT", uint32(windows.THREAD_GET_CONTEXT)},
	{"SET_CONTEXT", uint32(windows.THREAD_SET_CONTEXT)},
	{"SET_INFORMATION", uint32(windows.THREAD_SET_INFORMATION)},
	{"QUERY_INFORMATION", uint32(windows.THREAD_QUERY_INFORMATION)},
	{"SET_THREAD_TOKEN", uint32(windows.THREAD_SET_THREAD_TOKEN)},
	{"IMPERSONATE", uint32(windows.THREAD_IMPERSONATE)},
	{"DIRECT_IMPERSONATION", uint32(windows.THREAD_DIRECT_IMPERSONATION)},
	{"SET_LIMITED_INFORMATION", uint32(windows.THREAD_SET_LIMITED_INFORMATION)},
	{"QUERY_LIMITED_INFORMATION", uint32(windows.THREAD_QUERY_LIMITED_INFORMATION)},
}

// FileAttributeFlags describes file attribute flags.
var FileAttributeFlags = []ParamFlag{
	{"READ_ONLY", uint32(fs.FileReadOnly)},
}
