// +build windows

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

package object

import (
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
)

type genericMapping struct {
	GenericRead    uint32
	GenericWrite   uint32
	GenericExecute uint32
	GenericAll     uint32
}

// TypeInformation contains object type data.
type TypeInformation struct {
	TypeName                   utf16.UnicodeString
	TotalNumberOfObjects       uint32
	TotalNumberOfHandles       uint32
	TotalPagedPoolUsage        uint32
	TotalNonPagedPoolUsage     uint32
	TotalNamePoolUsage         uint32
	TotalHandleTableUsage      uint32
	HighWaterNumberOfObjects   uint32
	HighWaterNumberOfHandles   uint32
	HighWaterPagedPoolUsage    uint32
	HighWaterNonPagedPoolUsage uint32
	HighWaterNamePoolUsage     uint32
	HighWaterHandleTableUsage  uint32
	InvalidAttributes          uint32
	GenericMapping             genericMapping
	ValidAccessMask            uint32
	SecurityRequired           bool
	MaintainHandleCount        bool
	TypeIndex                  uint8
	ReservedByte               int8
	PoolType                   uint32
	DefaultPagedPoolCharge     uint32
	DefaultNonPagedPoolCharge  uint32
}

// TypesInformation stores the number of resolved object type names.
type TypesInformation struct {
	NumberOfTypes uint32
}

// NameInformation sotres object name information.
type NameInformation struct {
	ObjectName utf16.UnicodeString
}

// ProcessHandleTableEntryInfo is the structure that describes the process handle entry.
type ProcessHandleTableEntryInfo struct {
	Handle           handle.Handle
	HandleCount      uintptr
	PointerCount     uintptr
	GrantedAccess    uint32
	ObjectTypeIndex  uint32
	HandleAttributes uint32
	Reserved         uint32
}

// ProcessHandleSnapshotInformation is the structure that holds the process handle table.
type ProcessHandleSnapshotInformation struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]ProcessHandleTableEntryInfo
}

// SystemHandleTableEntryInfoEx is the structure that describes the process handle entry.
type SystemHandleTableEntryInfoEx struct {
	Object                uint64
	ProcessID             uintptr
	Handle                handle.Handle
	GrantedAccess         uint32
	CreatorBackTraceIndex uint8
	ObjectTypeIndex       uint8
	HandleAttributes      uint32
	Reserved              uint32
}

// SystemHandleInformationEx is the structures that holds the process handle table.
type SystemHandleInformationEx struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SystemHandleTableEntryInfoEx
}
