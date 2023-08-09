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
	"fmt"
	peparser "github.com/saferwall/pe"
	"reflect"
)

// IsHeaderModified returns true if any of the DOS, NT, or
// section headers located in on-disk PE structure differ from
// their in-memory representations.
func (pe *PE) IsHeaderModified(mem *PE) bool {
	var (
		epModified      bool
		archMismatch    bool
		dosHdrModified  bool
		ntHdrModified   bool
		fileHdrModified bool
		secHdrModified  bool
	)
	epModified = pe.EntryPoint != mem.EntryPoint
	archMismatch = pe.ntHeader.FileHeader.Machine != mem.ntHeader.FileHeader.Machine

	dosHdrModified = pe.isDOSHdrModified(mem)
	ntHdrModified = pe.isNTHdrModified(mem)
	fileHdrModified = pe.isFileHdrModified(mem)
	secHdrModified = pe.isSectionHdrModified(mem)

	if epModified {

	}
	if archMismatch {

	}
	fmt.Println(dosHdrModified, ntHdrModified, fileHdrModified, secHdrModified)

	return dosHdrModified || ntHdrModified || fileHdrModified || secHdrModified
}

func (pe *PE) isDOSHdrModified(mem *PE) bool {
	return !reflect.DeepEqual(pe.dosHeader, mem.dosHeader)
}

func (pe *PE) isNTHdrModified(mem *PE) bool {
	if pe.Is64 != mem.Is64 {
		return true
	}
	if pe.ntHeader == (peparser.ImageNtHeader{}) && mem.ntHeader == (peparser.ImageNtHeader{}) {
		return false
	}
	if pe.ntHeader == (peparser.ImageNtHeader{}) || mem.ntHeader == (peparser.ImageNtHeader{}) {
		return true
	}
	return !reflect.DeepEqual(pe.ntHeader, mem.ntHeader)
}

func (pe *PE) isFileHdrModified(mem *PE) bool {
	fileHeader, memHeader := pe.ntHeader.FileHeader, mem.ntHeader.FileHeader
	if fileHeader == (peparser.ImageFileHeader{}) && memHeader == (peparser.ImageFileHeader{}) {
		return false
	}
	if fileHeader == (peparser.ImageFileHeader{}) || memHeader == (peparser.ImageFileHeader{}) {
		return true
	}
	if fileHeader.Machine == memHeader.Machine &&
		fileHeader.Characteristics == memHeader.Characteristics &&
		fileHeader.NumberOfSections == memHeader.NumberOfSections &&
		fileHeader.TimeDateStamp == memHeader.TimeDateStamp &&
		fileHeader.SizeOfOptionalHeader != memHeader.SizeOfOptionalHeader { // SizeOfOptionalHeader differs
		return true
	}
	return false
}

func (pe *PE) isSectionHdrModified(mem *PE) bool {
	if pe.NumberOfSections != mem.NumberOfSections {
		return true
	}
	for n := uint16(0); n < pe.NumberOfSections; n++ {
		fileSecHeader := pe.sectionHeaders[n]
		memSecHeader := pe.sectionHeaders[n]
		if fileSecHeader == (peparser.ImageSectionHeader{}) && memSecHeader == (peparser.ImageSectionHeader{}) {
			continue
		}
		if fileSecHeader == (peparser.ImageSectionHeader{}) || memSecHeader == (peparser.ImageSectionHeader{}) {
			return true
		}
		if fileSecHeader.VirtualAddress != memSecHeader.VirtualAddress {
			return true
		}
		if fileSecHeader.VirtualSize != memSecHeader.VirtualSize {
			return true
		}
		if fileSecHeader.PointerToRawData != memSecHeader.PointerToRawData {
			return true
		}
	}
	return false
}
