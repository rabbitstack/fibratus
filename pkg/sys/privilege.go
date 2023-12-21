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
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	// SeDebugPrivilege is the name of the privilege used to debug programs.
	SeDebugPrivilege = "SeDebugPrivilege"
)

// Errors returned by AdjustTokenPrivileges.
const (
	// ErrorNotAllAsigned specifies that the token does not have one or more of the privileges specified in the state parameter.
	ErrorNotAllAsigned windows.Errno = 1300
)

// Attribute bits for privileges.
const (
	// PrivilegedEnabled enables the privilege.
	PrivilegedEnabled uint32 = 0x00000002
)

// mapPrivileges maps privilege names to LUID values.
func mapPrivileges(names []string) ([]windows.LUID, error) {
	var privileges []windows.LUID
	for _, name := range names {
		var p windows.LUID
		err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &p)
		if err != nil {
			return nil, errors.Wrapf(err, "LookupPrivilegeValue failed on '%v'", name)
		}
		privileges = append(privileges, p)
	}
	return privileges, nil
}

// EnableTokenPrivileges enables the specified privileges in the given
// Token. The token must have TOKEN_ADJUST_PRIVILEGES access. If the token
// does not already contain the privilege it cannot be enabled.
func EnableTokenPrivileges(token windows.Token, privileges ...string) error {
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

	privs := (*windows.Tokenprivileges)(unsafe.Pointer(&b.Bytes()[0]))
	err = windows.AdjustTokenPrivileges(token, false, privs, uint32(b.Len()), nil, nil)
	if err != nil {
		return err
	}
	if err == ErrorNotAllAsigned {
		return errors.Wrap(err, "error not all privileges were assigned")
	}
	return nil
}

// SetDebugPrivilege sets the debug privilege in the current running process.
func SetDebugPrivilege() {
	var token windows.Token
	_ = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	_ = EnableTokenPrivileges(token, SeDebugPrivilege)
}
