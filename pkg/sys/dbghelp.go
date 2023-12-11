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

package sys

import (
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	// SymCaseInsensitive causes all searches for symbol names to be case-insensitive.
	SymCaseInsensitive = 0x00000001

	// SymUndname specifies the symbol option that causes public symbol names
	// to be undecorated when they are displayed, and causes searches for symbol
	// names to ignore symbol decorations.
	SymUndname = 0x00000002

	// SymDeferredLoads this symbol option is called deferred symbol loading or
	// lazy symbol loading. When it is active, symbols are not actually loaded
	// when the target modules are loaded. Instead, symbols are loaded as they
	// are needed.
	SymDeferredLoads = 0x00000004

	// SymAutoPublics causes DbgHelp to search the public symbol table in a .pdb
	// file only as a last resort. If any matches are found when searching the
	// private symbol data, the public symbols will not be searched. This improves
	// symbol search speed.
	SymAutoPublics = 0x00010000

	// SymOmapFindNearest code has been optimized and there is no symbol at
	// the expected location, this option causes the nearest symbol to be used
	// instead.
	SymOmapFindNearest

	// MaxSymName specifies the maximum length of the symbol name.
	MaxSymName = 2000
)

// SymbolInfo contains symbol information.
type SymbolInfo struct {
	SizeStruct uint32
	TypeIndex  uint32
	Reserved   [2]uint64
	Index      uint32
	Size       uint32
	ModBase    uint64
	Flags      uint32
	Value      uint64
	Addr       uint64
	Register   uint32
	Scope      uint32
	Tag        uint32
	Length     uint32
	MaxLength  uint32
	Name       [1]uint16
}

// NewSymbolInfo creates a new instance of symbol info with pertinent initializations.
func NewSymbolInfo() *SymbolInfo {
	b := make([]byte, int(unsafe.Sizeof(SymbolInfo{}))+MaxSymName*2)
	sym := (*SymbolInfo)(unsafe.Pointer(&b[0]))
	sym.SizeStruct = uint32(unsafe.Sizeof(SymbolInfo{}))
	sym.MaxLength = uint32(MaxSymName)
	return sym
}

// SymbolName returns the symbol name.
func (s *SymbolInfo) SymbolName() string {
	if s.Length == 0 {
		return ""
	}
	return utf16.Decode((*[1 << 30]uint16)(unsafe.Pointer(&s.Name))[:s.Length:s.Length])
}

// ModuleInfo contains module information.
type ModuleInfo struct {
	SizeStruct      uint32
	ImageBase       uint64
	ImageSize       uint32
	TimeDateStamp   uint32
	Checksum        uint32
	NumSymbols      uint32
	SymType         int32
	ModuleName      [32]uint16
	ImageName       [256]uint16
	LoadedImageName [256]uint16
	LoadedPdbName   [256]uint16
	CVSig           uint32
	CVData          [780]uint16
	PdbSig          uint32
	PdbSig70        windows.GUID
	PdbAge          uint32
	PdbUnmatched    uint8
	DbgUnmatched    uint8
	LineNumbers     uint8
	GlobalSymbols   uint8
	TypeInfo        uint8
	SourceIndexed   uint8
	Publics         uint8
	MachineType     uint32
	Reserved        uint32
}

// NewModuleInfo creates a new instance of module info.
func NewModuleInfo() *ModuleInfo {
	return &ModuleInfo{
		SizeStruct: uint32(unsafe.Sizeof(ModuleInfo{})),
	}
}

// Name returns the module name.
func (m *ModuleInfo) Name() string {
	n := windows.UTF16ToString(m.ImageName[:])
	if n == "" {
		n = windows.UTF16ToString(m.ModuleName[:])
	}
	if n == "" {
		n = windows.UTF16ToString(m.LoadedImageName[:])
	}
	return n
}

// GetSymModuleName retrieves the module where the symbol is imported.
func GetSymModuleName(proc windows.Handle, addr uint64) string {
	mod := NewModuleInfo()
	if !SymGetModuleInfo(proc, addr, mod) {
		return "?"
	}
	module := mod.Name()
	if module == "" {
		return "?"
	}
	return module
}

// GetSymName retrieves the symbol name and offset for the given address.
func GetSymName(proc windows.Handle, addr uint64) (string, uint64) {
	sym := NewSymbolInfo()
	var offset uint64
	if !SymFromAddr(proc, addr, &offset, sym) {
		return "?", 0
	}
	symbol := sym.SymbolName()
	if symbol == "" {
		return "?", offset
	}
	return symbol, offset
}
