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
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/syscall/thread"
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
	{"ALL_ACCESS", uint32(process.AllAccess)},
	{"TERMINATE", uint32(process.Terminate)},
	{"CREATE_THREAD", uint32(process.CreateThread)},
	{"VM_OPERATION", uint32(process.VMOperation)},
	{"VM_READ", uint32(process.VMRead)},
	{"VM_WRITE", uint32(process.VMRead)},
	{"DUP_HANDLE", uint32(process.DupHandle)},
	{"CREATE_PROCESS", uint32(process.CreateProcess)},
	{"SET_QUOTA", uint32(process.SetQuota)},
	{"SET_INFORMATION", uint32(process.SetInformation)},
	{"QUERY_INFORMATION", uint32(process.QueryInformation)},
	{"SUSPEND_RESUME", uint32(process.SuspendResume)},
	{"QUERY_LIMITED_INFORMATION", uint32(process.QueryLimitedInformation)},
}

// ThreadAccessRightFlags describes flags for the thread access rights.
var ThreadAccessRightFlags = []ParamFlag{
	{"ALL_ACCESS", uint32(thread.AllAccess)},
	{"TERMINATE", uint32(thread.TerminateThread)},
	{"SUSPEND_THREAD", uint32(thread.SuspendResume)},
	{"GET_CONTEXT", uint32(thread.GetContext)},
	{"SET_CONTEXT", uint32(thread.SetContext)},
	{"SET_INFORMATION", uint32(thread.SetInformation)},
	{"QUERY_INFORMATION", uint32(thread.QueryInformation)},
	{"SET_THREAD_TOKEN", uint32(thread.SetThreadToken)},
	{"IMPERSONATE", uint32(thread.Impersonate)},
	{"DIRECT_IMPERSONATION", uint32(thread.DirectImpersonation)},
	{"SET_LIMITED_INFORMATION", uint32(thread.SetLimitedInformation)},
	{"QUERY_LIMITED_INFORMATION", uint32(thread.QueryLimitedInformation)},
}

// FileAttributeFlags describes file attribute flags.
var FileAttributeFlags = []ParamFlag{
	{"READ_ONLY", uint32(fs.FileReadOnly)},
}
