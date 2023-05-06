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
	"github.com/rabbitstack/fibratus/pkg/util/typesize"
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	// ObjectNameInformationClass returns the object name information.
	ObjectNameInformationClass = iota + 1
	// ObjectTypeInformationClass returns the object type information.
	ObjectTypeInformationClass
	// ObjectTypesInformationClass returns handle object types.
	ObjectTypesInformationClass
)

const (
	// AlpcBasicPortInformationClass is the information class for obtaining basic ALPC port information.
	AlpcBasicPortInformationClass = iota
)

const (
	// MutantBasicInformationClass is the information class for getting basic mutant information.
	MutantBasicInformationClass = iota
)

type GenericMapping struct {
	GenericRead    uint32
	GenericWrite   uint32
	GenericExecute uint32
	GenericAll     uint32
}

// ObjectTypeInformation contains object type data.
type ObjectTypeInformation struct {
	TypeName                   windows.NTUnicodeString
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
	GenericMapping             GenericMapping
	ValidAccessMask            uint32
	SecurityRequired           bool
	MaintainHandleCount        bool
	TypeIndex                  uint8
	ReservedByte               int8
	PoolType                   uint32
	DefaultPagedPoolCharge     uint32
	DefaultNonPagedPoolCharge  uint32
}

// ObjectTypesInformation stores the number of resolved object type names.
type ObjectTypesInformation struct {
	NumberOfTypes uint32
}

// First returns the first object type structure.
func (o *ObjectTypesInformation) First() *ObjectTypeInformation {
	p := unsafe.Pointer(uintptr(unsafe.Pointer(o)) + (unsafe.Sizeof(ObjectTypesInformation{})+typesize.Pointer()-1)&^(typesize.Pointer()-1))
	return (*ObjectTypeInformation)(p)
}

// Next returns the next object type structure given the previous structure pointer.
func (*ObjectTypesInformation) Next(typ *ObjectTypeInformation) *ObjectTypeInformation {
	align := (uintptr(typ.TypeName.MaximumLength) + typesize.Pointer() - 1) &^ (typesize.Pointer() - 1)
	offset := uintptr(unsafe.Pointer(typ)) + unsafe.Sizeof(ObjectTypeInformation{})
	return (*ObjectTypeInformation)(unsafe.Pointer(offset + align))
}

// ObjectNameInformation stores object name information.
type ObjectNameInformation struct {
	ObjectName windows.NTUnicodeString
}

func QueryObject[C any](obj windows.Handle, class int32) (*C, error) {
	var c C
	var s uint32
	n := make([]byte, unsafe.Sizeof(c))
	err := NtQueryObject(obj, class, unsafe.Pointer(&n[0]), uint32(len(n)), &s)
	if err != nil {
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW {
			n = make([]byte, s)
			err := NtQueryObject(obj, class, unsafe.Pointer(&n[0]), uint32(len(n)), &s)
			if err != nil {
				return nil, err
			}
			return (*C)(unsafe.Pointer(&n[0])), nil
		}
		return nil, err
	}
	return (*C)(unsafe.Pointer(&n[0])), nil
}
