//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

import "github.com/rabbitstack/fibratus/pkg/event/params"

const cloneThread = uint64(0x00010000)

// IsCreateProcess reports whether clone creates a new process.
func (e *Event) IsCreateProcess() bool {
	return e.Type == Clone && e.Params.TryGetUint64(params.CloneFlags)&cloneThread == 0
}

// IsCreateThread reports whether clone creates a thread in the current process.
func (e *Event) IsCreateThread() bool {
	return e.Type == Clone && e.Params.TryGetUint64(params.CloneFlags)&cloneThread != 0
}

// IsTerminateProcess reports whether the event exits a process.
func (e *Event) IsTerminateProcess() bool { return e.Type == Exit }

// PartialKey returns a key used to deduplicate sequence partials.
func (e *Event) PartialKey() uint64 {
	return uint64(e.Type)<<32 | uint64(e.PID)
}
