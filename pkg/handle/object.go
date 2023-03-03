//go:build windows
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

package handle

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/typesize"
	"github.com/rabbitstack/fibratus/pkg/zsyscall"
	"golang.org/x/sys/windows"
	"os"
	"sort"
	"unsafe"
)

var (
	// typesCount counts the number of resolved object type names
	typesCount = expvar.NewInt("handle.types.count")
	typeMisses = expvar.NewInt("handle.types.name.misses")
)

var devMapper = fs.NewDevMapper()

// ObjectTypeStore holds all object type names as exposed by the Object Manager. The store represents an efficient
// way of resolving object type indices to human-friendly names.
type ObjectTypeStore interface {
	FindByID(id uint8) string
	RegisterType(id uint8, typ string)
	TypeNames() []string
}

type otstore struct {
	types map[uint8]string
}

// NewObjectTypeStore creates a new object store instance.
func NewObjectTypeStore() ObjectTypeStore {
	s := &otstore{
		types: make(map[uint8]string),
	}
	s.queryTypes()
	return s
}

func (s *otstore) FindByID(id uint8) string {
	if typ, ok := s.types[id]; ok {
		return typ
	}
	typeMisses.Add(1)
	return ""
}

func (s *otstore) RegisterType(id uint8, typ string) {
	s.types[id] = typ
}

func (s *otstore) TypeNames() []string {
	types := make([]string, 0, len(s.types))
	for _, v := range s.types {
		types = append(types, v)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

func (s *otstore) queryTypes() {
	objectTypes, err := zsyscall.QueryObject[zsyscall.ObjectTypesInformation](0, zsyscall.ObjectTypesInformationClass)
	if err != nil {
		return
	}
	typesCount.Add(int64(objectTypes.NumberOfTypes))

	// heavily influenced by ProcessHacker pointer arithmetic hackery to
	// dereference the first and all subsequent file object type instances
	// starting from the address of the TypesInformation structure
	objectTypeInfo := (*zsyscall.ObjectTypeInformation)(s.first(objectTypes))
	for i := 0; i < int(objectTypes.NumberOfTypes); i++ {
		objectTypeInfo = (*zsyscall.ObjectTypeInformation)(s.next(objectTypeInfo))
		s.types[objectTypeInfo.TypeIndex] = objectTypeInfo.TypeName.String()
	}
}

func (s *otstore) first(types *zsyscall.ObjectTypesInformation) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(types)) + (unsafe.Sizeof(zsyscall.ObjectTypesInformation{})+typesize.Pointer()-1)&^(typesize.Pointer()-1))
}

func (s *otstore) next(typ *zsyscall.ObjectTypeInformation) unsafe.Pointer {
	align := (uintptr(typ.TypeName.MaximumLength) + typesize.Pointer() - 1) &^ (typesize.Pointer() - 1)
	offset := uintptr(unsafe.Pointer(typ)) + unsafe.Sizeof(zsyscall.ObjectTypeInformation{})
	return unsafe.Pointer(offset + align)
}

// Duplicate duplicates the handle in the caller process's address space.
func Duplicate(handle windows.Handle, pid uint32, access uint32) (windows.Handle, error) {
	//  handle to the process with the handle to be duplicated.
	source, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return windows.InvalidHandle, err
	}
	defer windows.CloseHandle(source)
	// this process receives the duplicated handle
	target, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(os.Getpid()))
	if err != nil {
		return windows.InvalidHandle, err
	}
	defer windows.CloseHandle(target)
	// duplicate the remote handle in the current process's address space.
	// Note that for certain handle types this operation might fail
	// as they don't permit duplicate operations
	var dup windows.Handle
	err = windows.DuplicateHandle(source, handle, target, &dup, access, false, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("unable to duplicate handle: %v", err)
	}
	return dup, nil
}

// QueryObjectType returns the type of the specified object.
func QueryObjectType(obj windows.Handle) (string, error) {
	typeInfo, err := zsyscall.QueryObject[zsyscall.ObjectTypeInformation](obj, zsyscall.ObjectTypeInformationClass)
	if err != nil {
		return "", fmt.Errorf("unable to query handle type: %v", err)
	}
	length := typeInfo.TypeName.Length
	if length > 0 {
		return typeInfo.TypeName.String(), nil
	}
	return "", errors.New("zero length handle type name encountered")
}

// QueryObjectName returns the object name of the specified object.
func QueryObjectName(obj windows.Handle) (string, error) {
	nameInfo, err := zsyscall.QueryObject[zsyscall.ObjectNameInformation](obj, zsyscall.ObjectNameInformationClass)
	if err != nil {
		return "", fmt.Errorf("unable to query object name: %v", err)
	}
	length := nameInfo.ObjectName.Length
	if length > 0 {
		return nameInfo.ObjectName.String(), nil
	}
	return "", nil
}

// QueryName gets the name of the underlying handle reference and extra metadata if it is available.
func QueryName(handle windows.Handle, typ string, withTimeout bool) (string, htypes.Meta, error) {
	switch typ {
	case File:
		if !withTimeout {
			return "", nil, nil
		}
		// delegate the name resolution to the deadlock aware handle timeout
		name, err := GetHandleWithTimeout(handle, 500)
		if err != nil {
			return "", nil, err
		}
		name = devMapper.Convert(name)
		fileInfo := &htypes.FileInfo{IsDirectory: zsyscall.PathIsDirectory(name)}
		return name, fileInfo, nil
	case ALPCPort:
		port, err := GetAlpcPort(handle)
		if err != nil {
			return "", nil, nil
		}
		return "", port, nil
	case Process:
		var size uint32 = windows.MAX_PATH
		n := make([]uint16, size)
		err := windows.QueryFullProcessImageName(handle, 0, &n[0], &size)
		if err != nil {
			return "", nil, err
		}
		return windows.UTF16ToString(n), nil, nil
	case Mutant:
		mutant, err := GetMutant(handle)
		if err != nil {
			return "", nil, nil
		}
		return "", mutant, nil
	default:
		name, err := QueryObjectName(handle)
		if err != nil {
			return "", nil, err
		}
		switch typ {
		case Key:
			rootKey, subkey := key.Format(name)
			if rootKey == key.Invalid {
				return name, nil, nil
			}
			if subkey != "" {
				return rootKey.String() + "\\" + subkey, nil, nil
			}
			return rootKey.String(), nil, nil
		default:
			return name, nil, nil
		}
	}
}
