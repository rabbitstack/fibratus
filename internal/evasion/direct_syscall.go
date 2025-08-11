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
	"github.com/rabbitstack/fibratus/pkg/event"
	"path/filepath"
	"strings"
)

// directSyscall direct syscall evasion refers to a technique where
// adversaries bypass traditional user-mode API monitoring and security
// hooks by invoking system calls directly, but does so in a way that
// evades detection or analysis.
//
// A direct syscall bypasses Windows API functions and calls the underlying
// system call directly using the syscall instruction, skipping the NTDLL
// stub that normally performs the transition to kernel mode.
type directSyscall struct{}

func NewDirectSyscall() Evasion {
	return &directSyscall{}
}

func (d *directSyscall) Eval(e *event.Event) (bool, error) {
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

	mod := filepath.Base(strings.ToLower(frame.Module))

	// check if the last userspace frame is originated
	// from the allowed modules such as the native NTDLL
	// module. If that's not the case, the process is
	// invoking a direct syscall
	return mod != "ntdll.dll" && mod != "win32.dll" && mod != "win32u.dll" && mod != "wow64win.dll" && mod != "wow64cpu.dll", nil
}

func (d *directSyscall) Type() Type { return DirectSyscall }
