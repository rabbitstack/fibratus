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

import (
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
)

// Source identifies a Linux event source.
type Source uint8

const (
	// RawSyscallTracepoint identifies events from the raw_syscalls tracepoint.
	RawSyscallTracepoint Source = iota
)

// Type identifies a Linux event type.
type Type uint16

const (
	UnknownType Type = iota
	Execve
	Exit
	Clone
)

// String returns the event type name.
func (t Type) String() string {
	switch t {
	case Execve:
		return "execve"
	case Exit:
		return "exit"
	case Clone:
		return "clone"
	default:
		return ""
	}
}

// Category returns the event type category.
func (t Type) Category() Category {
	switch t {
	case Execve, Exit, Clone:
		return Process
	default:
		return Unknown
	}
}

// Subcategory returns the event type subcategory.
func (t Type) Subcategory() Subcategory { return None }

// Description returns a brief description of the event type.
func (t Type) Description() string {
	switch t {
	case Execve:
		return "Executes a program"
	case Exit:
		return "Exit all threads in a process"
	case Clone:
		return "Creates a child process or a thread"
	default:
		return ""
	}
}

// Hash calculates the hash of the event type name.
func (t Type) Hash() uint32 {
	if t == UnknownType {
		return 0
	}
	return hashers.FnvUint32([]byte(t.String()))
}

// Exists reports whether the event type is known.
func (t Type) Exists() bool {
	switch t {
	case Execve, Exit, Clone:
		return true
	default:
		return false
	}
}

// UnmarshalYAML converts an event name to its type.
func (t *Type) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var name string
	if err := unmarshal(&name); err != nil {
		return err
	}
	*t = NameToType(name)
	return nil
}

// ID returns the stable numeric event identifier.
func (t Type) ID() uint { return uint(t) }

// Source returns the event source.
func (t Type) Source() Source { return RawSyscallTracepoint }

func (t Type) color() string {
	return colorizer.SpanBold(colorizer.White, t.String())
}

func (t Type) arrow() string {
	return colorizer.SpanBold(colorizer.Gray, "› ")
}
