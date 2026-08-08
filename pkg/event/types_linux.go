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

type Source uint8

const (
	SystemLogger Source = iota
	SecurityTelemetryLogger
)

type Type uint16

const (
	UnknownType Type = iota
	CreateProcess
	Execve
	TerminateProcess
	Exit
	ProcessRundown
	Clone

	// Windows-only event types stubbed so shared consumers (rules compiler)
	// compile on Linux. These are never emitted by the Linux event source.
	RegOpenKey
	OpenThread
	OpenProcess
	SetFileInformation
	CreateFile
	MapViewFile
	UnmapViewFile
	SetThreadContext
	CreateSymbolicLinkObject
	CreateThread
)

func (t Type) String() string {
	return TypeToEventInfo(t).Name
}

func (t Type) Category() Category {
	return TypeToEventInfo(t).Category
}

func (t Type) Subcategory() Subcategory {
	return None
}

func (t Type) Description() string {
	return TypeToEventInfo(t).Description
}

func (t Type) Hash() uint32 {
	if t == UnknownType {
		return 0
	}
	return hashers.FnvUint32([]byte(t.String()))
}

func (t Type) Exists() bool {
	return t != UnknownType && t.String() != "N/A"
}

func (t Type) OnlyState() bool {
	return t == ProcessRundown
}

func (t Type) CanEnrichStack() bool {
	return false
}

func (t *Type) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var name string
	if err := unmarshal(&name); err != nil {
		return err
	}
	*t = NameToType(name)
	return nil
}

func (t Type) ID() uint {
	return uint(t)
}

func (t Type) Source() Source {
	return SystemLogger
}

func (t Type) color() string {
	return colorizer.SpanBold(colorizer.White, t.String())
}

func (t Type) arrow() string {
	return colorizer.SpanBold(colorizer.Gray, "› ")
}
