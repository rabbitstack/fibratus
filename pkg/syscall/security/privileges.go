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

package security

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
	"sync"
	"syscall"
	"unsafe"
)

var (
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

// Cache of privilege names to LUIDs.
var (
	privNames     = make(map[string]int64)
	privNameMutex sync.Mutex
)

const (
	// SeDebugPrivilege is the name of the privilege used to debug programs.
	SeDebugPrivilege = "SeDebugPrivilege"
)

// Errors returned by AdjustTokenPrivileges.
const (
	// ErrorNotAllAsigned specifies that the token does not have one or more of the privileges specified in the state parameter.
	ErrorNotAllAsigned syscall.Errno = 1300
)

// Attribute bits for privileges.
const (
	// PrivilegedEnabled enables the privilege.
	PrivilegedEnabled uint32 = 0x00000002
)

func lookupPrivilegeValue(systemName string, name string, luid *int64) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(systemName)
	if err != nil {
		return
	}
	var _p1 *uint16
	_p1, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	return lookupPrivilegeValueW(_p0, _p1, luid)
}

func lookupPrivilegeValueW(systemName *uint16, name *uint16, luid *int64) (err error) {
	r1, _, e1 := syscall.Syscall(procLookupPrivilegeValueW.Addr(), 3, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(luid)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func adjustTokenPrivileges(token syscall.Token, releaseAll bool, input *byte, outputSize uint32, output *byte, requiredSize *uint32) (success bool, err error) {
	var _p0 uint32
	if releaseAll {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall6(procAdjustTokenPrivileges.Addr(), 6, uintptr(token), uintptr(_p0), uintptr(unsafe.Pointer(input)), uintptr(outputSize), uintptr(unsafe.Pointer(output)), uintptr(unsafe.Pointer(requiredSize)))
	success = r0 != 0
	if true {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// mapPrivileges maps privilege names to LUID values.
func mapPrivileges(names []string) ([]int64, error) {
	var privileges []int64
	privNameMutex.Lock()
	defer privNameMutex.Unlock()
	for _, name := range names {
		p, ok := privNames[name]
		if !ok {
			err := lookupPrivilegeValue("", name, &p)
			if err != nil {
				return nil, errors.Wrapf(err, "LookupPrivilegeValue failed on '%v'", name)
			}
			privNames[name] = p
		}
		privileges = append(privileges, p)
	}
	return privileges, nil
}

// EnableTokenPrivileges enables the specified privileges in the given
// Token. The token must have TOKEN_ADJUST_PRIVILEGES access. If the token
// does not already contain the privilege it cannot be enabled.
func EnableTokenPrivileges(token syscall.Token, privileges ...string) error {
	privValues, err := mapPrivileges(privileges)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, uint32(len(privValues))); err != nil {
		return err
	}
	for _, p := range privValues {
		if err := binary.Write(&b, binary.LittleEndian, p); err != nil {
			continue
		}
		if err := binary.Write(&b, binary.LittleEndian, PrivilegedEnabled); err != nil {
			continue
		}
	}

	success, err := adjustTokenPrivileges(token, false, &b.Bytes()[0], uint32(b.Len()), nil, nil)
	if !success {
		return err
	}
	if err == ErrorNotAllAsigned {
		return errors.Wrap(err, "error not all privileges were assigned")
	}

	return nil
}

// SetDebugPrivilege sets the debug privilege in the current running process.
func SetDebugPrivilege() {
	h, err := syscall.GetCurrentProcess()
	if err == nil {
		var token syscall.Token
		_ = syscall.OpenProcessToken(h, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token)
		_ = EnableTokenPrivileges(token, SeDebugPrivilege)
	}
}
