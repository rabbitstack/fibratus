/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package threadcontext

import (
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Context contains processor-specific register data.
type Context struct {
	P1           uint64
	P2           uint64
	P3           uint64
	P4           uint64
	P5           uint64
	P6           uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
}

// Decode reads the thread context structure from
// the given process memory and at the specified
// base address. Returns the decoded Context struct
// or nil if the data cannot be read from the remote
// process address space.
func Decode(pid uint32, addr va.Address) *Context {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil
	}
	defer windows.Close(proc)

	size := uint(unsafe.Sizeof(Context{}))
	ctx := va.ReadArea(proc, addr.Uintptr(), size, size, false)
	if !va.Zeroed(ctx) {
		return (*Context)(unsafe.Pointer(&ctx[0]))
	}

	return nil
}

// Rip returns the address stored in the instruction pointer register.
func Rip(pid uint32, addr va.Address) va.Address {
	ctx := Decode(pid, addr)
	if ctx != nil {
		return va.Address(ctx.Rip)
	}
	return 0
}

// IsParamOfFunc returns true if the CONTEXT
// structure is supplied as a single parameter
// to the well-known API functions.
func IsParamOfFunc(f string) bool {
	return f == "NtContinue" || f == "ZwContinue" || f == "RtlCaptureContext"
}
