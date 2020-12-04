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

package resource

import (
	"encoding/binary"
)

// ID is the type for identifying resource types
type ID uint32

const (
	Version ID = 16 // Version defines version resources
)

// String yields a human-readable resource type name.
func (id ID) String() string {
	switch id {
	case Version:
		return "RT_VERSION"
	default:
		return ""
	}
}

// Directory represents the layout of the resource directory.
type Directory struct {
	Characteristics    uint32
	Timestamp          uint32
	Major              uint16
	Minor              uint16
	NumberNamedEntries uint16
	NumberIDEntries    uint16
}

// Size returns the size in bytes of the resource directory.
func (d Directory) Size() int { return binary.Size(d) }

// DirectoryEntry defines the entry in the directory table.
type DirectoryEntry struct {
	Name         uint32
	OffsetToData uint32
}

// Size returns the size in bytes of the resource entry.
func (e DirectoryEntry) Size() int { return binary.Size(e) }

// ID returns the type of the resource.
func (e DirectoryEntry) ID() ID {
	if !e.IsString() {
		return ID(e.Name)
	}
	return ID(e.Name & 0x0000FFF)
}

// IsString determines if this resource contains string data.
func (e DirectoryEntry) IsString() bool { return ((e.Name & 0x80000000) >> 31) > 0 }

// IsDir indicates if this resource entry is a directory instead of resource final data.
func (e DirectoryEntry) IsDir() bool { return ((e.OffsetToData & 0x80000000) >> 31) > 0 }

// DirOffset returns the offset into the resource directory.
func (e DirectoryEntry) DirOffset() uint32 { return e.OffsetToData & 0x7FFFFFFF }

// DataEntry stores the offset to the resource data.
type DataEntry struct {
	OffsetToData uint32
	DataSize     uint32
	CodePage     uint32
	Reserved     uint32
}

// Size returns the size in bytes of the resource data.
func (e DataEntry) Size() int { return binary.Size(e) }

// VersionInfo contains information about version entries.
type VersionInfo struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// Size returns the size of this structure.
func (v VersionInfo) Size() int { return binary.Size(v) }

// FixedFileinfo stores attributes that describe the FixedFileInformation entries.
type FixedFileinfo struct {
	Signature        uint32
	StructVer        uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagMask     uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

// Size returns the size of this structure in bytes.
func (f FixedFileinfo) Size() int { return binary.Size(f) }

// StringFileInfo contains information about string file info entries.
type StringFileInfo struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// Size returns the size of this structure in bytes.
func (s StringFileInfo) Size() int { return binary.Size(s) }

// Skip decides whether to ignore processing the StringFileInfo entries.
func (s StringFileInfo) Skip() bool { return (s.Type != 0 && s.Type != 1) && s.ValueLength != 0 }

// StringTable contains information about string table entries.
type StringTable struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// Size returns the size of this structure in bytes.
func (s StringTable) Size() int { return binary.Size(s) }

// String contains information about string entries.
type String struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// Size returns the size of this structure.
func (s String) Size() int { return binary.Size(s) }
