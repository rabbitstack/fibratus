//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package event

import (
	"encoding/json"
	"fmt"

	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
)

func (e *Event) IsCreateFile() bool             { return false }
func (e *Event) IsCreateProcess() bool          { return e.Type == CreateProcess || e.Type == Execve || e.Type == Clone }
func (e *Event) IsCreateProcessInternal() bool  { return false }
func (e *Event) IsCreateThread() bool           { return false }
func (e *Event) IsCloseFile() bool              { return false }
func (e *Event) IsCreateHandle() bool           { return false }
func (e *Event) IsCloseHandle() bool            { return false }
func (e *Event) IsDeleteFile() bool             { return false }
func (e *Event) IsRenameFile() bool             { return false }
func (e *Event) IsEnumDirectory() bool          { return false }
func (e *Event) IsTerminateProcess() bool       { return e.Type == TerminateProcess || e.Type == Exit }
func (e *Event) IsTerminateThread() bool        { return false }
func (e *Event) IsUnloadModule() bool           { return false }
func (e *Event) IsLoadModule() bool             { return false }
func (e *Event) IsLoadModuleInternal() bool     { return false }
func (e *Event) IsModuleRundown() bool          { return false }
func (e *Event) IsFileOpEnd() bool              { return false }
func (e *Event) IsRegSetValue() bool            { return false }
func (e *Event) IsRegSetValueInternal() bool    { return false }
func (e *Event) IsRegCreateKey() bool           { return false }
func (e *Event) IsProcessRundown() bool         { return e.Type == ProcessRundown }
func (e *Event) IsProcessRundownInternal() bool { return false }
func (e *Event) IsVirtualAlloc() bool           { return false }
func (e *Event) IsMapViewFile() bool            { return false }
func (e *Event) IsUnmapViewFile() bool          { return false }
func (e *Event) IsStackWalk() bool              { return false }
func (e *Event) IsOpenThread() bool             { return false }
func (e *Event) IsOpenProcess() bool            { return false }
func (e *Event) IsNetworkTCP() bool             { return false }
func (e *Event) IsNetworkUDP() bool             { return false }
func (e *Event) IsDNS() bool                    { return false }
func (e *Event) IsRundown() bool                { return e.IsProcessRundown() }
func (e *Event) IsSuccess() bool                { return true }
func (e *Event) IsRundownProcessed() bool       { return false }
func (e *Event) IsCreateDisposition() bool      { return false }
func (e *Event) IsOverwriteDisposition() bool   { return false }
func (e *Event) IsOpenDisposition() bool        { return false }
func (e *Event) IsCreateRemoteThread() bool     { return false }
func (e *Event) IsSurrogateProcess() bool       { return false }
func (e *Event) IsSystemPid() bool              { return e.PID == 0 || e.PID == 1 }
func (e *Event) IsState() bool                  { return e.Type.OnlyState() }

// PartialKey returns a key used to deduplicate sequence partials.
// On Linux this combines the event type with the process identifier.
func (e *Event) PartialKey() uint64 {
	return uint64(e.Type)<<32 | uint64(e.PID)
}

// HookID returns the stable bitset index for this type.
func (t Type) HookID() uint16 { return uint16(t) }

// MarshalJSON serializes the event to JSON.
func (e *Event) MarshalJSON() []byte {
	b, err := json.Marshal(e)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// UnmarshalRaw recovers the event from a capture buffer.
// Captures are not wired on Linux yet.
func (e *Event) UnmarshalRaw(_ []byte, _ capver.Version) error {
	return fmt.Errorf("event capture unmarshalling is not implemented on Linux")
}
