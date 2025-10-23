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

import "github.com/rabbitstack/fibratus/pkg/event"

// Type is the alias for the evasion technique type.
type Type uint8

const (
	// DirectSyscall represents the direct syscall evasion.
	DirectSyscall Type = iota
	// IndirectSyscall represents the indirect syscall evasion.
	IndirectSyscall
)

// String returns the evasion human-friendly name.
func (t Type) String() string {
	switch t {
	case DirectSyscall:
		return "direct_syscall"
	case IndirectSyscall:
		return "indirect_syscall"
	default:
		return "unknown"
	}
}

// Evasion defines the contract that all evasion detectors need to satisfy.
type Evasion interface {
	// Eval executes the evasion logic. The evasion detector usually accesses
	// the callstack from the given event to determine if any evasions are
	// performed on behalf of the process. If the evasion is recognized, this
	// method return true, or false otherwise.
	Eval(*event.Event) (bool, error)
	// Type returns the type of the evasion technique.
	Type() Type
}
