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

package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	peparser "github.com/saferwall/pe"
)

const (
	// VersionResourceType identifies the version resource type in the resource directory
	VersionResourceType = 16

	// VsVersionInfoString is the UTF16-encoded string that identifies the VS_VERSION_INFO block
	VsVersionInfoString = "VS_VERSION_INFO"

	// VsFileInfoSignature is the file info signature
	VsFileInfoSignature uint32 = 0xFEEF04BD

	// StringFileInfoString is the UTF16-encoded string that identifies the StringFileInfo block
	StringFileInfoString = "StringFileInfo"
	VarFileInfoString    = "VarFileInfo"

	// VsVersionInfoStringLength specifies the length of the VS_VERSION_INFO structure
	VsVersionInfoStringLength uint32 = 6
	// StringFileInfoLength specifies the offset of the file info Unicode string
	StringFileInfoLength uint32 = 6
	StringTableLength    uint32 = 6
	StringLength         uint32 = 6
	LangIDLength         uint32 = 8*2 + 1
)

// VsVersionInfo represents the organization of data in
// a file-version resource. It is the root structure that
// contains all other file-version information structures.
type VsVersionInfo struct {
	// Length is the length, in bytes, of the VS_VERSIONINFO structure.
	// This length does not include any padding that aligns any
	// subsequent version resource data on a 32-bit boundary.
	Length uint16
	// ValueLength is the length, in bytes, of arbitrary data associated
	// with the VS_VERSIONINFO structure.
	// This value is zero if there is no any data associated with the
	// current version structure.
	ValueLength uint16
	// Type represents as many zero words as necessary to align the StringFileInfo
	// and VarFileInfo structures on a 32-bit boundary. These bytes are not included
	// in ValueLength.
	Type uint16
}

// Parse parses the VS_VERSIONINFO structure from resource directory entry.
func (v *VsVersionInfo) Parse(e peparser.ResourceDirectoryEntry, pe *peparser.File) error {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData)
	b, err := pe.ReadBytesAtOffset(offset, e.Data.Struct.Size)
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, v); err != nil {
		return err
	}
	b, err = pe.ReadBytesAtOffset(offset+VsVersionInfoStringLength, uint32(v.ValueLength))
	if err != nil {
		return err
	}
	vsVersionString, err := DecodeUTF16String(b)
	if err != nil {
		return err
	}
	if vsVersionString != VsVersionInfoString {
		return fmt.Errorf("invalid VS_VERSION_INFO block. %s", vsVersionString)
	}
	return nil
}

// VsFixedFileInfo contains version information for a file.
// This information is language and code page independent.
type VsFixedFileInfo struct {
	// Signature Contains the value 0xFEEF04BD. This is used
	// with the `key` member of the VS_VERSIONINFO structure
	// when searching a file for the VS_FIXEDFILEINFO structure.
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
func (f *VsFixedFileInfo) Size() uint32 { return uint32(binary.Size(f)) }

func (f *VsFixedFileInfo) GetStringFileInfoOffset(e peparser.ResourceDirectoryEntry) uint32 {
	return AlignDword(VsVersionInfoStringLength+uint32(2*len(VsVersionInfoString)+1)+f.Size(), e.Data.Struct.OffsetToData)
}

func (f *VsFixedFileInfo) GetOffset(e peparser.ResourceDirectoryEntry, pe *peparser.File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + VsVersionInfoStringLength
	offset += uint32(2*len(VsVersionInfoString)) + 1
	return AlignDword(offset, e.Data.Struct.OffsetToData)
}

func (f *VsFixedFileInfo) Parse(e peparser.ResourceDirectoryEntry, pe *peparser.File) error {
	offset := f.GetOffset(e, pe)
	b, err := pe.ReadBytesAtOffset(offset, f.Size())
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, f); err != nil {
		return err
	}
	if f.Signature != VsFileInfoSignature {
		return fmt.Errorf("invalid file info signature %d", f.Signature)
	}
	return nil
}

// StringFileInfo represents the organization of data in a
// file-version resource. It contains version information
// that can be displayed for a particular language and code page.
type StringFileInfo struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// ContainsData determines if the resource contains text or binary data.
func (s *StringFileInfo) ContainsData() bool {
	return s.Length > 0 && (s.Type == 0 || s.Type == 1)
}

func (s *StringFileInfo) GetStringTableOffset(offset uint32) uint32 {
	return offset + StringFileInfoLength + uint32(2*len(StringFileInfoString)) + 1
}

func (s *StringFileInfo) GetOffset(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return AlignDword(offset, e.Data.Struct.OffsetToData)
}

func (s *StringFileInfo) Parse(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) (string, error) {
	offset := s.GetOffset(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringFileInfoLength)
	if err != nil {
		return "", err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, s); err != nil {
		return "", err
	}
	b, err = pe.ReadBytesAtOffset(offset+StringFileInfoLength, uint32(len(StringFileInfoString)*2)+1)
	if err != nil {
		return "", err
	}
	return DecodeUTF16String(b)
}

// StringTable represents the organization of data in a
// file-version resource. It contains language and code
// page formatting information for the version strings
type StringTable struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func (s *StringTable) GetStringOffset(offset uint32, e peparser.ResourceDirectoryEntry) uint32 {
	return AlignDword(offset+StringTableLength+LangIDLength, e.Data.Struct.OffsetToData)
}

func (s *StringTable) GetOffset(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return AlignDword(offset, e.Data.Struct.OffsetToData)
}

func (s *StringTable) Parse(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) error {
	offset := s.GetOffset(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringTableLength)
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, s); err != nil {
		return err
	}
	// Read the 8-digit hexadecimal number stored as a Unicode string.
	// The four most significant digits represent the language identifier.
	// The four least significant digits represent the code page for which
	// the data is formatted.
	b, err = pe.ReadBytesAtOffset(offset+StringTableLength, (8*2)+1)
	if err != nil {
		return err
	}
	langID, err := DecodeUTF16String(b)
	if err != nil {
		return err
	}
	if len(langID) != int(LangIDLength/2) {
		return fmt.Errorf("invalid language identifier length. Expected: %d, Got: %d",
			LangIDLength/2,
			len(langID))
	}
	return nil
}

// String Represents the organization of data in a
// file-version resource. It contains a string that
// describes a specific aspect of a file, for example,
// a file's version, its copyright notices, or its trademarks.
type String struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func (s *String) GetOffset(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return AlignDword(offset, e.Data.Struct.OffsetToData)
}

func (s *String) Parse(rva uint32, e peparser.ResourceDirectoryEntry, pe *peparser.File) (string, string, error) {
	offset := s.GetOffset(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringLength)
	if err != nil {
		return "", "", err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, s); err != nil {
		return "", "", err
	}
	const maxKeySize = 100
	b, err = pe.ReadBytesAtOffset(offset+StringLength, maxKeySize)
	if err != nil {
		return "", "", err
	}
	key, err := DecodeUTF16String(b)
	if err != nil {
		return "", "", err
	}
	valueOffset := AlignDword(uint32(2*(len(key)+1))+offset+StringLength, e.Data.Struct.OffsetToData)
	b, err = pe.ReadBytesAtOffset(valueOffset, uint32(s.Length))
	if err != nil {
		return "", "", err
	}
	value, err := DecodeUTF16String(b)
	if err != nil {
		return "", "", err
	}
	return key, value, nil
}

// ParseVersionResources parser file version strings from the version resource
// directory.
func ParseVersionResources(pe *peparser.File) (map[string]string, error) {
	vers := make(map[string]string)
	for _, e := range pe.Resources.Entries {
		if e.ID != VersionResourceType {
			continue
		}
		directory := e.Directory.Entries[0].Directory
		for _, e := range directory.Entries {
			var ver VsVersionInfo
			var ff VsFixedFileInfo

			err := ver.Parse(e, pe)
			if err != nil {
				return vers, err
			}
			err = ff.Parse(e, pe)
			if err != nil {
				return vers, err
			}
			offset := ff.GetStringFileInfoOffset(e)
			for {
				f := StringFileInfo{}
				n, err := f.Parse(offset, e, pe)
				if err != nil || f.Length == 0 {
					break
				}
				switch n {
				case StringFileInfoString:
					tableOffset := f.GetStringTableOffset(offset)
					for {
						table := StringTable{}
						err := table.Parse(tableOffset, e, pe)
						if err != nil {
							break
						}
						stringOffset := table.GetStringOffset(tableOffset, e)
						for stringOffset < tableOffset+uint32(table.Length) {
							s := String{}
							k, v, err := s.Parse(stringOffset, e, pe)
							if err != nil {
								break
							}
							if s.Length == 0 {
								stringOffset = tableOffset + uint32(table.Length)
							} else {
								stringOffset = stringOffset + uint32(s.Length)
							}
							vers[k] = v
						}
						// handle potential infinite loops
						if uint32(table.Length)+tableOffset > tableOffset {
							break
						}
						if tableOffset > uint32(f.Length) {
							break
						}
					}
				case VarFileInfoString:
					break
				default:
					break
				}
				offset += uint32(f.Length)
				// StringFileInfo/VarFileinfo structs consumed?
				if offset >= uint32(ver.Length) {
					break
				}
			}
		}
	}
	return vers, nil
}
