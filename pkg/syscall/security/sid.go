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
	"errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"os"
	"syscall"
	"unsafe"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	netapi32 = syscall.NewLazyDLL("netapi32.dll")

	lookupAccountSid = advapi32.NewProc("LookupAccountSidW")
	netUserEnum      = netapi32.NewProc("NetUserEnum")
	netBufferFree    = netapi32.NewProc("NetApiBufferFree")
)

const (
	userMaxPreferredLength = 0xFFFFFFFF
)

// LookupAccount returns the account and domain name from a security identifier.
func LookupAccount(buffer []byte, wbemSID bool) (string, string) {
	n := uint32(50)
	dn := uint32(50)
	sid := uintptr(unsafe.Pointer(&buffer[0]))

	if wbemSID {
		// a WBEM SID is actually a TOKEN_USER structure followed
		// by the SID, so we have to double the pointer size
		sid += uintptr(8 * 2)
	}
	var accType uint32
	for {
		b := make([]uint16, n)
		db := make([]uint16, dn)
		errno, _, _ := lookupAccountSid.Call(
			0,
			sid,
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(unsafe.Pointer(&n)),
			uintptr(unsafe.Pointer(&db[0])),
			uintptr(unsafe.Pointer(&dn)),
			uintptr(unsafe.Pointer(&accType)),
			0,
			0)

		if winerrno.Errno(errno) != winerrno.Success {
			return syscall.UTF16ToString(b), syscall.UTF16ToString(db)
		}
		if winerrno.Errno(errno) != winerrno.InsufficientBuffer {
			return "", ""
		}
		if n <= uint32(len(b)) {
			return "", ""
		}
	}
}

type userInfo struct {
	name *uint16
}

// LookupAllSids returns SIDs for each user account in the system.
func LookupAllSids() ([]string, error) {
	var (
		buf    uintptr
		handle uintptr
		read   uint32
		total  uint32
	)

	errno, _, err := netUserEnum.Call(
		uintptr(0),
		uintptr(uint32(0)),
		uintptr(0),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(uint32(userMaxPreferredLength)),
		uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if winerrno.Errno(errno) != winerrno.Success {
		return nil, os.NewSyscallError("NetUserEnum", err)
	}

	if buf == uintptr(0) {
		return nil, os.NewSyscallError("NetUserEnum", errors.New("null buffer pointer"))
	}
	sids := make([]string, 0)
	entry := buf
	for i := uint32(0); i < read; i++ {
		info := (*userInfo)(unsafe.Pointer(entry))
		if info == nil {
			continue
		}
		username := syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(info.name))[:])
		sid, _, _, err := syscall.LookupSID("", username)
		if err != nil {
			continue
		}
		s, err := sid.String()
		if err != nil {
			continue
		}
		sids = append(sids, s)
		entry = uintptr(unsafe.Pointer(entry + unsafe.Sizeof(userInfo{})))
	}
	_, _, _ = netBufferFree.Call(buf)
	return sids, nil
}
