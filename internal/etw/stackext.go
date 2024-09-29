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
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

// StackExtensions manages stack tracing enablement
// for particular event or event categories.
type StackExtensions struct {
	ids    []etw.ClassicEventID
	config config.KstreamConfig
}

// NewStackExtensions creates an empty stack extensions.
func NewStackExtensions(config config.KstreamConfig) *StackExtensions {
	return &StackExtensions{ids: make([]etw.ClassicEventID, 0), config: config}
}

// AddStackTracing enables stack tracing for the specified event type.
func (s *StackExtensions) AddStackTracing(ktype ktypes.Ktype) {
	if !s.config.TestDropMask(ktype) {
		s.ids = append(s.ids, etw.NewClassicEventID(ktype.GUID(), ktype.HookID()))
	}
}

// AddStackTracingWith enables stack tracing for the specified provider GUID and event hook id.
func (s *StackExtensions) AddStackTracingWith(guid windows.GUID, hookID uint16) {
	if !s.config.TestDropMask(ktypes.FromParts(guid, hookID)) {
		s.ids = append(s.ids, etw.NewClassicEventID(guid, hookID))
	}
}

// EventIds returns all event types eligible for stack tracing.
func (s *StackExtensions) EventIds() []etw.ClassicEventID { return s.ids }

// EnableProcessStackTracing populates the stack identifiers
// with event types eligible for emitting stack walk events
// related to process telemetry, such as creating a process,
// creating/terminating a thread or loading an image into
// process address space.
func (s *StackExtensions) EnableProcessStackTracing() {
	s.AddStackTracing(ktypes.CreateProcess)
	if s.config.EnableThreadKevents {
		s.AddStackTracing(ktypes.CreateThread)
		s.AddStackTracing(ktypes.TerminateThread)
	}
	if s.config.EnableImageKevents {
		s.AddStackTracingWith(ktypes.ProcessEventGUID, ktypes.LoadImage.HookID())
	}
}

// EnableFileStackTracing populates the stack identifiers
// with event types eligible for publishing call stack
// return addresses for file system activity.
func (s *StackExtensions) EnableFileStackTracing() {
	if s.config.EnableFileIOKevents {
		s.AddStackTracing(ktypes.CreateFile)
		s.AddStackTracing(ktypes.DeleteFile)
		s.AddStackTracing(ktypes.RenameFile)
	}
}

// EnableRegistryStackTracing populates the stack identifiers
// with event types eligible for publishing call stack
// return addresses for registry operations.
func (s *StackExtensions) EnableRegistryStackTracing() {
	if s.config.EnableRegistryKevents {
		s.AddStackTracing(ktypes.RegCreateKey)
		s.AddStackTracing(ktypes.RegDeleteKey)
		s.AddStackTracing(ktypes.RegSetValue)
		s.AddStackTracing(ktypes.RegDeleteValue)
	}
}
