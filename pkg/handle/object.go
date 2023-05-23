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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"golang.org/x/sys/windows"
	"os"
)

var devMapper = fs.NewDevMapper()

// Duplicate duplicates the handle in the caller process's address space.
func Duplicate(handle windows.Handle, pid uint32, access uint32) (windows.Handle, error) {
	//  handle to the process with the handle to be duplicated.
	source, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return windows.InvalidHandle, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(source)
	// this process receives the duplicated handle
	target, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(os.Getpid()))
	if err != nil {
		return windows.InvalidHandle, err
	}
	//nolint:errcheck
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
	typeInfo, err := sys.QueryObject[sys.ObjectTypeInformation](obj, sys.ObjectTypeInformationClass)
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
	nameInfo, err := sys.QueryObject[sys.ObjectNameInformation](obj, sys.ObjectNameInformationClass)
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
		fileInfo := &htypes.FileInfo{IsDirectory: sys.PathIsDirectory(name)}
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
