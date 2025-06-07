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

package etw

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

// StackExtensions manages stack tracing enablement
// for particular event or event categories.
type StackExtensions struct {
	ids    []etw.ClassicEventID
	config config.EventSourceConfig
}

// NewStackExtensions creates an empty stack extensions.
func NewStackExtensions(config config.EventSourceConfig) *StackExtensions {
	return &StackExtensions{ids: make([]etw.ClassicEventID, 0), config: config}
}

// AddStackTracing enables stack tracing for the specified event type.
func (s *StackExtensions) AddStackTracing(typ event.Type) {
	if !s.config.TestDropMask(typ) {
		s.ids = append(s.ids, etw.NewClassicEventID(typ.GUID(), typ.HookID()))
	}
}

// AddStackTracingWith enables stack tracing for the specified provider GUID and event hook id.
func (s *StackExtensions) AddStackTracingWith(guid windows.GUID, hookID uint16) {
	if !s.config.TestDropMask(event.TypeFromParts(guid, hookID)) {
		s.ids = append(s.ids, etw.NewClassicEventID(guid, hookID))
	}
}

// EventIds returns all event types eligible for stack tracing.
func (s *StackExtensions) EventIds() []etw.ClassicEventID { return s.ids }

// Empty determines if this stack extensions has registered event identifiers.
func (s *StackExtensions) Empty() bool { return len(s.ids) == 0 }

// EnableProcessCallstack populates the stack identifiers
// with event types eligible for emitting stack walk events
// related to process telemetry, such as creating a process,
// creating/terminating a thread or loading an image into
// process address space.
func (s *StackExtensions) EnableProcessCallstack() {
	s.AddStackTracing(event.CreateProcess)
	if s.config.EnableThreadEvents {
		s.AddStackTracing(event.CreateThread)
		s.AddStackTracing(event.TerminateThread)
	}
	if s.config.EnableImageEvents {
		s.AddStackTracingWith(event.ProcessEventGUID, event.LoadImage.HookID())
	}
}

// EnableFileCallstack populates the stack identifiers
// with event types eligible for publishing call stack
// return addresses for file system activity.
func (s *StackExtensions) EnableFileCallstack() {
	if s.config.EnableFileIOEvents {
		s.AddStackTracing(event.CreateFile)
		s.AddStackTracing(event.DeleteFile)
		s.AddStackTracing(event.RenameFile)
	}
}

// EnableRegistryCallstack populates the stack identifiers
// with event types eligible for publishing call stack
// return addresses for registry operations.
func (s *StackExtensions) EnableRegistryCallstack() {
	if s.config.EnableRegistryEvents {
		s.AddStackTracing(event.RegCreateKey)
		s.AddStackTracing(event.RegDeleteKey)
		s.AddStackTracing(event.RegSetValue)
		s.AddStackTracing(event.RegDeleteValue)
	}
}

// EnableMemoryCallstack enables stack tracing for the memory
// events such as memory allocations.
func (s *StackExtensions) EnableMemoryCallstack() {
	if s.config.EnableMemEvents {
		s.AddStackTracing(event.VirtualAlloc)
	}
}

// EnableThreadpoolCallstack enables stack tracing for thread pool events.
func (s *StackExtensions) EnableThreadpoolCallstack() {
	if s.config.EnableThreadpoolEvents {
		s.AddStackTracing(event.SubmitThreadpoolWork)
		s.AddStackTracing(event.SubmitThreadpoolCallback)
		s.AddStackTracing(event.SetThreadpoolTimer)
	}
}
