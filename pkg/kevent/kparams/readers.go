//go:build windows
// +build windows

/*
 * Copyright 2022-2023 by Nedim Sabic Sabic
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

package kparams

import (
	"syscall"
	"unsafe"
)

// ReadByte reads the byte from the buffer at the specified offset.
func ReadByte(buf uintptr, offset uint16) byte {
	return *(*byte)(unsafe.Pointer(buf + uintptr(offset)))
}

// ReadUint16 reads the uint16 value from the buffer at the specified offset.
func ReadUint16(buf uintptr, offset uint16) uint16 {
	return *(*uint16)(unsafe.Pointer(buf + uintptr(offset)))
}

// ReadUint32 reads the uint32 value from the buffer at the specified offset.
func ReadUint32(buf uintptr, offset uint16) uint32 {
	return *(*uint32)(unsafe.Pointer(buf + uintptr(offset)))
}

// ReadUint64 reads the uint64 value from the buffer at the specified offset.
func ReadUint64(buf uintptr, offset uint16) uint64 {
	return *(*uint64)(unsafe.Pointer(buf + uintptr(offset)))
}

// ReadUTF8String reads the UTF-8 string from the buffer at the specified offset and buffer length.
func ReadUTF8String(buf uintptr, offset, length uint16) (string, uint16) {
	if offset > length {
		return "", 0
	}
	b := make([]byte, length)
	var i uint16
	for i < length {
		c := *(*byte)(unsafe.Pointer(buf + uintptr(offset) + uintptr(i)))
		if c == 0 {
			break // null terminator
		}
		b[i] = c
		i++
	}
	if int(i) > len(b) {
		return string(b[:len(b)-1]), uint16(len(b))
	}
	return string(b[:i]), i + 1
}

// ReadUTF16String reads the UTF-16 string from the buffer at the specified offset and buffer length.
func ReadUTF16String(buf uintptr, offset, length uint16) (string, uint16) {
	if offset > length {
		return "", 0
	}
	// scan the entire string
	b := make([]uint16, length)
	var i uint16
	for i < length-offset {
		c := *(*uint16)(unsafe.Pointer(buf + uintptr(offset) + uintptr(i)))
		if c == 0 {
			break // null terminator
		}
		b[i] = c
		i++
	}
	if int(i) > len(b) {
		return string(syscall.UTF16ToString(b[:len(b)-1])), uint16(len(b))
	}
	return syscall.UTF16ToString(b[:i]), i + 2
}

// ConsumeString reads the byte slice with UTF16-encoded string
// when the length is known upfront.
func ConsumeString(buf uintptr, offset, length uint16) string {
	if offset > length {
		return ""
	}
	s := (*[1<<30 - 1]uint16)(unsafe.Pointer(buf + uintptr(offset)))[: length-offset-1 : length-offset-1]
	return syscall.UTF16ToString(s)
}

// ReadSID reads the security identifier from the provided buffer.
func ReadSID(buf uintptr, offset uint16) ([]byte, uint16) {
	// this is a Security Token which can be null and takes 4 bytes.
	// Otherwise it is an 8 byte structure (TOKEN_USER) followed by SID,
	// which is variable size depending on the 2nd byte in the SID
	sid := ReadUint32(buf, offset)
	if sid == 0 {
		return nil, offset + 4
	}
	const tokenSize uint16 = 16

	authorities := ReadByte(buf, offset+(tokenSize+1))
	end := offset + tokenSize + 8 + 4*uint16(authorities)
	b := make([]byte, end-offset)
	i := offset
	for i < end {
		b[i-offset] = *(*byte)(unsafe.Pointer(buf + uintptr(i)))
		i++
	}
	return b, end
}
