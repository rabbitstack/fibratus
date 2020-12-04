/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package section

import (
	"fmt"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
)

// Section represents the header describing the type, length and the version of each section.
type Section [10]byte

// String returns the string representation of the kcap section.
func (s Section) String() string {
	return fmt.Sprintf("type: %s, version: %d, len: %d, size: %d", s.Type(), s.Version(), s.Len(), s.Size())
}

// Type describes the type of a section
type Type uint8

const (
	// Process is the process header type
	Process Type = iota + 1
	// Handle is the handle header type
	Handle
	// Kevt is the kernel event header type
	Kevt
	// PE is the Portable Executable header type
	PE
)

// String returns the type name.
func (s Type) String() string {
	switch s {
	case Process:
		return "process"
	case Handle:
		return "handle"
	case Kevt:
		return "kevent"
	case PE:
		return "pe"
	default:
		return ""
	}
}

// New buils a new section block with the specified type, version, optional length and size.
func New(typ Type, ver kcapver.Version, l, size uint32) Section {
	var s Section
	s[0] = uint8(typ)
	s[1] = uint8(ver)
	copy(s[2:6], bytes.WriteUint32(l))
	copy(s[6:], bytes.WriteUint32(size))
	return s
}

// Read reads the section from the byte slice.
func Read(b []byte) Section {
	var s Section
	copy(s[:], b)
	return s
}

// Type returns the type of this section.
func (s Section) Type() Type { return Type(s[0]) }

// Version returns the version of the captured section block.
func (s Section) Version() kcapver.Version { return kcapver.Version(s[1]) }

// Len returns the length of the section.
func (s Section) Len() uint32 { return bytes.ReadUint32(s[2:6]) }

// Size returns the size of the section.
func (s Section) Size() uint32 { return bytes.ReadUint32(s[6:]) }
