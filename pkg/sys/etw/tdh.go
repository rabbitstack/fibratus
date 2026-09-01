//go:build windows
// +build windows

/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TraceEventInfo mirrors TRACE_EVENT_INFO (evntcons.h / tdh.h). Only the
// fixed header is modeled here — EventPropertyInfoArray is variable-length
// and starts immediately after this struct in the buffer; we don't need it
// for name resolution, only the *Offset fields, which are self-relative
// offsets into the SAME buffer TDH wrote into (not absolute pointers), so
// parsing is a plain slice index, not an unsafe.Pointer dereference against
// the original EventRecord memory.
type TraceEventInfo struct {
	ProviderGuid          windows.GUID
	EventGuid             windows.GUID
	EventDescriptor       EventDescriptor
	DecodingSource        uint32
	ProviderNameOffset    uint32
	LevelNameOffset       uint32
	ChannelNameOffset     uint32
	KeywordsNameOffset    uint32
	TaskNameOffset        uint32
	OpcodeNameOffset      uint32
	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32
	BinaryXMLSize         uint32
	EventNameOffset       uint32 // union w/ ActivityIDNameOffset in the real struct
	EventAttributesOffset uint32 // union w/ RelatedActivityIDNameOffset
	PropertyCount         uint32
	TopLevelPropertyCount uint32
	Flags                 uint32
}

// GetEventTaskName resolves the TDH-decoded task name (e.g. "Ast.IoctlCalled")
// for a live EVENT_RECORD, using the standard two-call sizing pattern: call
// once with a zero buffer size to learn the required size, then again with
// an allocated buffer.
func GetEventTaskName(r *EventRecord) (string, error) {
	var bufferSize uint32

	// First call: expect ERROR_INSUFFICIENT_BUFFER, which is how TDH
	// reports the required size — not a real failure.
	err := tdhGetEventInformation(r, 0, 0, nil, &bufferSize)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("tdhGetEventInformation (sizing): %w", err)
	}
	if bufferSize == 0 {
		return "", fmt.Errorf("tdhGetEventInformation: zero buffer size returned")
	}

	buf := make([]byte, bufferSize)
	if err := tdhGetEventInformation(r, 0, 0, &buf[0], &bufferSize); err != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("tdhGetEventInformation: %w", err)
	}

	info := (*TraceEventInfo)(unsafe.Pointer(&buf[0]))

	name := utf16FromOffset(buf, info.TaskNameOffset)
	if name == "" {
		// Some events (manifest quirks, or genuinely task-less events)
		// won't have a task name even when EventNameOffset does — worth
		// falling back rather than treating this as an error.
		name = utf16FromOffset(buf, info.EventNameOffset)
	}
	return name, nil
}

// utf16FromOffset reads a null-terminated UTF-16 string starting at a
// self-relative byte offset into buf. TDH writes all *Offset fields
// relative to the start of the buffer it filled, not as absolute pointers,
// so this is a plain slice reinterpretation — no cross-buffer unsafe
// pointer arithmetic needed.
func utf16FromOffset(buf []byte, offset uint32) string {
	if offset == 0 || int(offset) >= len(buf) {
		return ""
	}
	p := (*uint16)(unsafe.Pointer(&buf[offset]))
	return windows.UTF16PtrToString(p)
}
