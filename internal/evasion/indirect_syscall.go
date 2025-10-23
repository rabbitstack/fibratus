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

package evasion

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var syscallStubs = map[event.Type]string{
	event.CreateProcess:            "NtCreateUserProcess",
	event.CreateThread:             "NtCreateThreadEx",
	event.TerminateThread:          "NtTerminateThread",
	event.RegCreateKey:             "NtCreateKey",
	event.RegDeleteKey:             "NtDeleteKey",
	event.RegSetValue:              "NtSetValueKey",
	event.RegDeleteValue:           "NtDeleteValueKey",
	event.SetThreadContext:         "NtSetContextThread",
	event.OpenProcess:              "NtOpenProcess",
	event.OpenThread:               "NtOpenThread",
	event.VirtualAlloc:             "NtAllocateVirtualMemory",
	event.CreateFile:               "NtCreateFile",
	event.DeleteFile:               "NtDeleteFile",
	event.RenameFile:               "NtSetInformationFile",
	event.CreateSymbolicLinkObject: "NtCreateSymbolicLinkObject",
}

const syscallStubLength = 23

// indirectSyscall evasion refers to executing the syscall instruction by
// diverting the execution flow into a legitimate, clean ntdll stub that
// performs the syscall on process behalf.
//
// This achieves code origin legitimacy, since the execution lands in .text
// of a signed Microsoft module (ntdll.dll). Stack frames look identical to
// a normal API call, which achieves call stack normalization.
type indirectSyscall struct {
	offsets map[event.Type]uintptr // stores expected syscall stub offsets
}

func NewIndirectSyscall() Evasion {
	return &indirectSyscall{}
}

func (i *indirectSyscall) tryResolveSyscallStubOffsets(e *event.Event) error {
	if i.offsets != nil {
		return nil
	}

	var ntdllBase va.Address
	if e.PS != nil {
		for _, mod := range e.PS.Modules {
			if mod.IsNTDLL() {
				ntdllBase = mod.BaseAddress
			}
		}
	}

	if ntdllBase.IsZero() {
		return nil
	}

	var handle windows.Handle
	if err := windows.GetModuleHandleEx(sys.ModuleHandleFromAddress, (*uint16)(unsafe.Pointer(ntdllBase.Uintptr())), &handle); err != nil {
		return err
	}
	defer windows.Close(handle)

	i.offsets = make(map[event.Type]uintptr)

	for evt, stub := range syscallStubs {
		addr, err := windows.GetProcAddress(handle, stub)
		if err != nil {
			log.Warnf("unable to get procedure address for %s: %v", evt, err)
			continue
		}
		i.offsets[evt] = addr - ntdllBase.Uintptr()
		log.Debugf("syscall stub %s resolved to address %x and offset %d", evt, addr, i.offsets[evt])
	}

	return nil
}

func (i *indirectSyscall) Eval(e *event.Event) (bool, error) {
	if err := i.tryResolveSyscallStubOffsets(e); err != nil {
		return false, err
	}
	if e.Callstack.IsEmpty() {
		return false, nil
	}

	frame := e.Callstack.FinalUserspaceFrame()
	if frame == nil {
		return false, nil
	}

	if frame.IsUnbacked() {
		return false, nil
	}

	sym := frame.Symbol
	mod := filepath.Base(strings.ToLower(frame.Module))

	if mod != "ntdll.dll" {
		// only check ntdll syscall stubs
		return false, nil
	}

	// eliminate common false positives (there are
	// many other false positives that can be directly
	// tuned in the rules)
	switch {
	case e.IsCreateProcess() && sym == "ZwDeviceIoControlFile" && e.Callstack.ContainsSymbol("AttachConsole"):
		return false, nil
	case e.IsCreateThread() && (sym == "ZwSetInformationWorkerFactory" || sym == "ZwReleaseWorkerFactoryWorker"):
		return false, nil
	case e.IsOpenThread() && sym == "ZwAlpcOpenSenderThread":
		return false, nil
	case e.IsOpenProcess() && sym == "ZwAlpcOpenSenderProcess":
		return false, nil
	case e.IsCreateFile() && (sym == "ZwOpenFile" || sym == "NtOpenFile" || sym == "ZwQueryAttributesFile" || sym == "ZwQueryFullAttributesFile" || sym == "ZwQueryInformationByName" || sym == "ZwQuerySystemInformation"):
		return false, nil
	case e.IsDeleteFile() && (sym == "ZwSetInformationFile" && (e.Callstack.ContainsSymbol("DeleteFileA") || e.Callstack.ContainsSymbol("DeleteFileW"))):
		return false, nil
	case e.IsRegCreateKey() && sym == "ZwDeviceIoControlFile" && e.Callstack.ContainsSymbol("DllUnregisterServer"):
		return false, nil
	}

	exp, ok := i.offsets[e.Type]
	if !ok {
		return false, nil
	}
	curr := frame.Addr.Dec(uint64(frame.ModuleAddress)).Uintptr()

	//nolint:staticcheck
	return !(curr > exp && curr <= exp+syscallStubLength), nil
}

func (*indirectSyscall) Type() Type { return IndirectSyscall }
