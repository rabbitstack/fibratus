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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	maxEnvSize = 4096
)

// PEB contains various process's metadata from the Process Environment Block (PEB). PEB is an opaque data structure
// that contains information that apply across a whole process, including global context, startup parameters, data structures
// for the program image loader, the program image base address, and synchronization objects used to provide mutual exclusion
// for process-wide data structures. Although it is not encouraged to access this structure due to its unstable nature, some
// process's information like command line or environments strings are only available through Process Environment Block fields.
type PEB struct {
	peb        *process.PEB
	handle     handle.Handle
	procParams *process.RTLUserProcessParameters
}

// ReadPEB queries the process's basic information class structures and copies the PEB into
// the current process's address space. Returns the reference to the PEB of the process that is being queried.
func ReadPEB(handle handle.Handle) (*PEB, error) {
	buf := make([]byte, unsafe.Sizeof(process.BasicInformation{}))
	_, err := process.QueryInfo(handle, process.BasicInformationClass, buf)
	if err != nil {
		return nil, fmt.Errorf("couldn't query process information: %v", err)
	}
	info := (*process.BasicInformation)(unsafe.Pointer(&buf[0]))
	// read the PEB to get the process parameters. Because the PEB structure resides
	// in the address space of another process we must read the memory block in order
	// to access the structure's fields.
	peb, err := process.ReadMemory(handle, unsafe.Pointer(info.PEB), unsafe.Sizeof(process.PEB{}))
	if err != nil {
		return nil, fmt.Errorf("coulnd't read PEB: %v", err)
	}
	return &PEB{peb: (*process.PEB)(unsafe.Pointer(&peb[0])), handle: handle}, nil
}

// GetImage inspects the process image name by reading the memory buffer in the PEB.
func (p PEB) GetImage() string {
	params, err := p.readProcessParams()
	if err != nil {
		return ""
	}
	image, err := process.ReadMemoryUnicode(p.handle, unsafe.Pointer(params.ImagePathName.Buffer), uintptr(params.ImagePathName.Length))
	if err != nil {
		return ""
	}
	return syscall.UTF16ToString(image)
}

// GetCommandLine inspects the process command line arguments by reading the memory buffer in the PEB.
func (p PEB) GetCommandLine() string {
	params, err := p.readProcessParams()
	if err != nil {
		return ""
	}
	comm, err := process.ReadMemoryUnicode(p.handle, unsafe.Pointer(params.CommandLine.Buffer), uintptr(params.CommandLine.Length))
	if err != nil {
		return ""
	}
	return syscall.UTF16ToString(comm)
}

// GetCurrentWorkingDirectory reads the current working directory from the PEB.
func (p PEB) GetCurrentWorkingDirectory() string {
	params, err := p.readProcessParams()
	if err != nil {
		return ""
	}
	cwd, err := process.ReadMemoryUnicode(p.handle, unsafe.Pointer(params.CurrentDirectory.DosPath.Buffer), uintptr(params.CurrentDirectory.DosPath.Length))
	if err != nil {
		return ""
	}
	return syscall.UTF16ToString(cwd)
}

// GetEnvs returns the map of environment variables that were mapped into the process PEB.
func (p PEB) GetEnvs() map[string]string {
	params, err := p.readProcessParams()
	if err != nil {
		return nil
	}
	// we can read the whole memory region starting from the env address
	// and speculate the size of the env block, but we just use a fixed
	// buffer size
	s, err := process.ReadMemoryUnicode(p.handle, unsafe.Pointer(params.Environment), uintptr(maxEnvSize))
	if err != nil {
		return nil
	}
	envs := make(map[string]string)
	start, end := 0, 0
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
			if kv := strings.Split(env, "="); len(kv) == 2 {
				envs[kv[0]] = kv[1]
			}
			start = end + 1
		}
	}
	return envs
}

// readProcessParams reads the `RtlUserProcessParameters` struct
// which contains the command line and the image name of the process
func (p *PEB) readProcessParams() (*process.RTLUserProcessParameters, error) {
	if p.procParams != nil {
		return p.procParams, nil
	}
	b, err := process.ReadMemory(p.handle, unsafe.Pointer(p.peb.ProcessParameters), unsafe.Sizeof(process.RTLUserProcessParameters{}))
	if err != nil {
		return nil, fmt.Errorf("couldn't read process's parameters from PEB: %v", err)
	}
	p.procParams = (*process.RTLUserProcessParameters)(unsafe.Pointer(&b[0]))
	return p.procParams, nil
}
