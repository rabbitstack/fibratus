//go:build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/util/key"
)

// NewParamFromCapture builds a parameter instance from the restored capture state.
func NewParamFromCapture(name string, typ params.Type, value params.Value, etype Type) *Param {
	var enum ParamEnum
	var flags ParamFlags
	switch name {
	case params.FileOperation:
		enum = fs.FileCreateDispositions
	case params.FileCreateOptions:
		flags = FileCreateOptionsFlags
	case params.FileAttributes:
		flags = FileAttributeFlags
	case params.FileShareMask:
		flags = FileShareModeFlags
	case params.FileInfoClass:
		enum = fs.FileInfoClasses
	case params.FileType:
		enum = fs.FileTypes
	case params.NetL4Proto:
		enum = network.ProtoNames
	case params.RegValueType:
		enum = key.RegistryValueTypes
	case params.MemAllocType:
		flags = MemAllocationFlags
	case params.FileViewSectionType:
		enum = ViewSectionTypes
	case params.DNSOpts:
		flags = DNSOptsFlags
	case params.DNSRR:
		enum = DNSRecordTypes
	case params.DNSRcode:
		enum = DNSResponseCodes
	case params.DesiredAccess:
		if etype == OpenProcess {
			flags = PsAccessRightFlags
		} else {
			flags = ThreadAccessRightFlags
		}
	case params.MemProtect:
		if etype == VirtualAlloc || etype == VirtualFree {
			flags = MemProtectionFlags
		} else {
			flags = ViewProtectionFlags
		}
	}
	return &Param{Name: name, Type: typ, Value: value, Enum: enum, Flags: flags}
}
