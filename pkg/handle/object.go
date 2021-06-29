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
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/syscall/file"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/object"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/syscall/registry"
	"github.com/rabbitstack/fibratus/pkg/util/typesize"
	"os"
	"sort"
	"unsafe"
)

var (
	// typeBufSize specifies the size of the object type name buffer
	typeBufSize = 512
	// nameBufSize specifies the size of the object name buffer
	nameBufSize = 1024
	// typesCount counts the number of resolved object type names
	typesCount = expvar.NewInt("handle.types.count")
	typeMisses = expvar.NewInt("handle.types.name.misses")
)

var devMapper = fs.NewDevMapper()

// ObjectTypeStore holds all object type names as exposed by the Object Manager. The store represents a efficient
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
	bufSize := 8824
	buf := make([]byte, bufSize)
	size, err := object.Query(0, object.TypesInformationClass, buf)
	if err == errs.ErrNeedsReallocateBuffer {
		buf = make([]byte, size)
		if _, err = object.Query(0, object.TypesInformationClass, buf); err != nil {
			return
		}
	}

	if err != nil {
		return
	}

	types := (*object.TypesInformation)(unsafe.Pointer(&buf[0]))
	typesCount.Add(int64(types.NumberOfTypes))

	// heavily influenced by ProcessHacker pointer arithmetic hackery to
	// dereference the first and all subsequent file object type instances
	// starting from the address of the TypesInformation structure
	objectTypeInfo := (*object.TypeInformation)(s.first(buf))
	for i := 0; i < int(types.NumberOfTypes); i++ {
		objectTypeInfo = (*object.TypeInformation)(s.next(objectTypeInfo))
		s.types[objectTypeInfo.TypeIndex] = objectTypeInfo.TypeName.String()
	}
}

func (s *otstore) first(b []byte) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + (unsafe.Sizeof(object.TypesInformation{})+typesize.Pointer()-1)&^(typesize.Pointer()-1))
}

func (s *otstore) next(typ *object.TypeInformation) unsafe.Pointer {
	align := (uintptr(typ.TypeName.MaxLength) + typesize.Pointer() - 1) &^ (typesize.Pointer() - 1)
	offset := uintptr(unsafe.Pointer(typ)) + unsafe.Sizeof(object.TypeInformation{})
	return unsafe.Pointer(offset + align)
}

// Duplicate duplicates the handle in the caller process's address space.
func Duplicate(h handle.Handle, pid uint32, access handle.DuplicateAccess) (handle.Handle, error) {
	targetPs, err := process.Open(process.DupHandle, false, pid)
	if err != nil {
		return ^handle.Handle(0), err
	}
	defer targetPs.Close()
	currentPs, err := process.Open(process.DupHandle, false, uint32(os.Getpid()))
	if err != nil {
		return ^handle.Handle(0), err
	}
	defer currentPs.Close()
	// duplicate the remote handle in the current process's address space.
	// Note that for certain handle types this operation might fail
	// as they don't permit duplicate operations
	dup, err := h.Duplicate(targetPs, currentPs, access)
	if err != nil {
		return ^handle.Handle(0), fmt.Errorf("couldn't duplicate handle: %v", err)
	}
	return dup, nil
}

// QueryType returns the type of the specified handle.
func QueryType(handle handle.Handle) (string, error) {
	buffer := make([]byte, typeBufSize)
	size, err := object.Query(handle, object.TypeInformationClass, buffer)
	if err == errs.ErrNeedsReallocateBuffer {
		buffer = make([]byte, size)
		if _, err = object.Query(handle, object.TypeInformationClass, buffer); err != nil {
			return "", fmt.Errorf("couldn't query handle type after buffer reallocation: %v", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("couldn't query handle type: %v", err)
	}
	// transform buffer into type information structure and get
	// the underlying UNICODE string that identifies handle's type name
	typeInfo := (*object.TypeInformation)(unsafe.Pointer(&buffer[0]))
	length := typeInfo.TypeName.Length
	if length > 0 {
		return typeInfo.TypeName.String(), nil
	}
	return "", errors.New("zero length handle type name encountered")
}

// QueryName gets the name of the underlying handle reference and extra metadata if it is available.
func QueryName(handle handle.Handle, typ string, withTimeout bool) (string, htypes.Meta, error) {
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
		fileInfo := &htypes.FileInfo{IsDirectory: file.IsPathDirectory(name)}
		return name, fileInfo, nil
	case ALPCPort:
		port, err := GetAlpcPort(handle)
		if err != nil {
			return "", nil, nil
		}
		return "", port, nil
	case Process:
		name, err := process.QueryFullImageName(handle)
		if err != nil {
			return "", nil, nil
		}
		return name, nil, nil
	case Mutant:
		mutant, err := GetMutant(handle)
		if err != nil {
			return "", nil, nil
		}
		return "", mutant, nil
	default:
		name, err := queryObjectName(handle)
		if err != nil {
			return "", nil, err
		}
		switch typ {
		case Key:
			key, subkey := FormatKey(name)
			rootKey := key.String()
			if key == registry.InvalidKey {
				return name, nil, nil
			}
			if subkey != "" {
				return rootKey + "\\" + subkey, nil, nil
			}
			return key.String(), nil, nil
		default:
			return name, nil, nil
		}
	}
}

func queryObjectName(handle handle.Handle) (string, error) {
	buffer := make([]byte, nameBufSize)
	size, err := object.Query(handle, object.NameInformationClass, buffer)
	if err == errs.ErrNeedsReallocateBuffer {
		buffer = make([]byte, size)
		if _, err = object.Query(handle, object.NameInformationClass, buffer); err != nil {
			return "", fmt.Errorf("couldn't query handle name after buffer reallocation: %v", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("couldn't query handle name: %v", err)
	}
	nameInfo := (*object.NameInformation)(unsafe.Pointer(&buffer[0]))
	length := nameInfo.ObjectName.Length
	if length > 0 {
		return nameInfo.ObjectName.String(), nil
	}
	return "", nil
}
