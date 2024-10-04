//go:build windows
// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package ps

import (
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"strings"
	"unicode/utf16"
	"unsafe"
)

// PEB contains various process's metadata from the Process Environment Block (PEB). PEB is an opaque data structure
// that contains information that apply across a whole process, including global context, startup parameters, data structures
// for the program image loader, the program image base address, and synchronization objects used to provide mutual exclusion
// for process-wide data structures. Although it is not encouraged to access this structure due to its unstable nature, some
// process's information like command line or environments strings are only available through Process Environment Block fields.
type PEB struct {
	peb        *windows.PEB
	procParams *windows.RTL_USER_PROCESS_PARAMETERS
	proc       windows.Handle
}

// ReadPEB queries the process's basic information class structures and copies the PEB into
// the current process's address space.
func ReadPEB(proc windows.Handle) (*PEB, error) {
	peb := &PEB{proc: proc}
	pbi, err := sys.QueryInformationProcess[windows.PROCESS_BASIC_INFORMATION](proc, windows.ProcessBasicInformation)
	if err != nil {
		return nil, err
	}
	// read the PEB to get the process parameters. Because the PEB structure resides
	// in the address space of another process we must read the memory block in order
	// to access the structure's fields.
	peb.peb, err = sys.ReadProcessMemory[windows.PEB](proc, uintptr(unsafe.Pointer(pbi.PebBaseAddress)))
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_NOACCESS ||
			err == windows.ERROR_PARTIAL_COPY {
			return peb, nil
		}
		return nil, err
	}
	// read the `RTL_USER_PROCESS_PARAMETERS` struct which contains the command line
	// and the image name of the process among many other attributes.
	peb.procParams, err = sys.ReadProcessMemory[windows.RTL_USER_PROCESS_PARAMETERS](proc, uintptr(unsafe.Pointer(peb.peb.ProcessParameters)))
	if err != nil {
		return nil, err
	}
	return peb, nil
}

// GetImage inspects the process image name by reading the memory buffer in the PEB.
func (p PEB) GetImage() string {
	if p.procParams == nil {
		return ""
	}
	image := readUTF16(p.proc, uniptr(p.procParams.ImagePathName.Buffer), uint32(p.procParams.ImagePathName.Length))
	return windows.UTF16ToString(image)
}

// GetCommandLine inspects the process command line arguments by reading the memory buffer in the PEB.
func (p PEB) GetCommandLine() string {
	if p.procParams == nil {
		return ""
	}
	cmdline := readUTF16(p.proc, uniptr(p.procParams.CommandLine.Buffer), uint32(p.procParams.CommandLine.Length))
	return windows.UTF16ToString(cmdline)
}

// GetCurrentWorkingDirectory reads the current working directory from the PEB.
func (p PEB) GetCurrentWorkingDirectory() string {
	if p.procParams == nil {
		return ""
	}
	cwd := readUTF16(p.proc, uniptr(p.procParams.CurrentDirectory.DosPath.Buffer), uint32(p.procParams.CurrentDirectory.DosPath.Length))
	return windows.UTF16ToString(cwd)
}

// GetSessionID returns the process session identifier.
func (p PEB) GetSessionID() uint32 {
	if p.peb == nil {
		return 0
	}
	return p.peb.SessionId
}

// GetEnvs returns the map of environment variables that were mapped into the process PEB.
func (p PEB) GetEnvs() map[string]string {
	if p.procParams == nil {
		return nil
	}
	start, end := 0, 0
	envs := make(map[string]string)
	l := uint32(p.procParams.EnvironmentSize)
	s := readUTF16(p.proc, uintptr(p.procParams.Environment), l)
	for i, r := range s {
		// each env variable key/value pair terminates with the NUL character
		if r == 0 {
			end = i
		}
		if end > start {
			// the next token starts with a NUL character
			// which means we have consumed all env variables
			if s[start] == 0 {
				break
			}
			env := string(utf16.Decode(s[start:end]))
			if kv := strings.SplitN(env, "=", 2); len(kv) == 2 {
				envs[kv[0]] = kv[1]
			}
			start = end + 1
		}
	}
	return envs
}

func readUTF16(proc windows.Handle, addr uintptr, size uint32) []uint16 {
	b := make([]byte, size*2+1)
	err := windows.ReadProcessMemory(proc, addr, &b[0], uintptr(len(b)), nil)
	if err != nil {
		return nil
	}
	l := uintptr(len(b)) * unsafe.Sizeof(b[0]) / unsafe.Sizeof(uint16(0))
	s := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), l)
	return s
}

func uniptr(b *uint16) uintptr { return uintptr(unsafe.Pointer(b)) }
