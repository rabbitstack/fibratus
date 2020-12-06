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

package utf16

import (
	"reflect"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// UnicodeString stores the size and the memory buffer of the unicode string.
type UnicodeString struct {
	Length    uint16
	MaxLength uint16
	Buffer    *uint16
}

// String returns the native string from the Unicode stream.
func (u UnicodeString) String() string {
	if u.Length == 0 {
		return ""
	}
	var s []uint16
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(u.Buffer))
	hdr.Len = int(u.Length / 2)
	hdr.Cap = int(u.MaxLength / 2)
	return string(utf16.Decode(s))
}

// StringToUTF16Ptr returns the pointer to UTF-8 encoded string. It will silently return
// an invalid pointer if `s` argument contains a NUL byte at any location.
func StringToUTF16Ptr(s string) *uint16 {
	var p *uint16
	p, _ = syscall.UTF16PtrFromString(s)
	return p
}

// PtrToString is like UTF16ToString, but takes *uint16
// as a parameter instead of []uint16.
func PtrToString(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	var s []uint16
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(p)
	hdr.Cap = 1
	hdr.Len = 1
	for s[len(s)-1] != 0 {
		hdr.Cap++
		hdr.Len++
	}
	// Remove trailing NUL and decode into a Go string.
	return string(utf16.Decode(s[:len(s)-1]))
}
