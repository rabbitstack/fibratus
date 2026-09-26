//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
)

// Source identifies a Linux event source.
type Source uint8

const (
	// RawSyscallTracepoint identifies events from the raw syscall tracepoint.
	RawSyscallTracepoint Source = iota
)

// Type identifies a Linux event type.
type Type uint16

const (
	Unknown Type = iota
	Execve
	Exit
	Clone
	Openat
	Unlink
	Rename
	Connect
	Accept
	Mmap
	ProcessVMRead
	ProcessVMWrite
	Kill
	Ptrace
	Prctl
	MaxEvent
)

// String returns the event type string representation.
func (t Type) String() string { return table[t].Name }

func (t Type) color() string {
	return colorizer.SpanBold(colorizer.White, t.String())
}

func (t Type) arrow() string {
	return colorizer.SpanBold(colorizer.Gray, "› ")
}
