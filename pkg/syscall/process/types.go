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

package process

import "github.com/rabbitstack/fibratus/pkg/syscall/utf16"

type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [21]byte
	LDR                    *LDRData
	ProcessParameters      *RTLUserProcessParameters
	Reserved3              [520]byte
	PostProcessInitRoutine uintptr
	Reserved4              [136]byte
	SessionID              uint32
}

type BasicInformation struct {
	Reserved1                    uintptr
	PEB                          *PEB
	Reserved2                    [2]uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

type String struct {
	Length        uint8
	MaximumLength uint8
}

type RTLUserProcessParameters struct {
	Reserved1        [16]byte
	consoleHandle    uintptr
	consoleFlags     uint32
	stdin            uintptr
	stdout           uintptr
	stderr           uintptr
	CurrentDirectory CurDir
	dllPath          utf16.UnicodeString
	ImagePathName    utf16.UnicodeString
	CommandLine      utf16.UnicodeString
	Environment      uintptr
}

type CurDir struct {
	DosPath utf16.UnicodeString
	Handle  uintptr
}

type LDRData struct {
	Reserved1  [8]byte
	Reserved2  [3]uintptr
	ModuleList ListEntry
}

type ListEntry struct {
	Flink *ListEntry
	Blink *ListEntry
}
