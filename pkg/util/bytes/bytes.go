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

package bytes

import (
	"encoding/binary"
	"unsafe"
)

// NativeEndian represents the endianness of the current machine
var NativeEndian binary.ByteOrder

func init() {
	InitNativeEndian(nil)
}

// InitNativeEndian figures out the endianness of the current machine (https://stackoverflow.com/questions/51332658/any-better-way-to-check-endianness-in-go)
func InitNativeEndian(b []byte) {
	buf := [8]byte{}
	if len(b) == 8 {
		copy(buf[:], b[:8])
	} else {
		*(*uint64)(unsafe.Pointer(&buf[0])) = uint64(0x6669627261747573)
	}

	switch buf {
	case [8]byte{0x73, 0x75, 0x74, 0x61, 0x72, 0x62, 0x69, 0x66}:
		NativeEndian = binary.LittleEndian
	case [8]byte{0x66, 0x69, 0x62, 0x72, 0x61, 0x74, 0x75, 0x73}:
		NativeEndian = binary.BigEndian
	default:
		panic("could not determine native endianness")
	}
}

// ReadUint16 reads the uint16 value from the byte slice.
func ReadUint16(b []byte) uint16 {
	return NativeEndian.Uint16(b)
}

// ReadUint32 reads the uint32 value from the byte slice.
func ReadUint32(b []byte) uint32 {
	return NativeEndian.Uint32(b)
}

// ReadUint64 reads the uint64 value from the byte slice.
func ReadUint64(b []byte) uint64 {
	return NativeEndian.Uint64(b)
}

// WriteUint16 writes the provided uint16 value to byte slice.
func WriteUint16(v uint16) (b []byte) {
	b = make([]byte, 2)
	NativeEndian.PutUint16(b, v)
	return
}

// WriteUint32 writes the provided uint32 value to byte slice.
func WriteUint32(v uint32) (b []byte) {
	b = make([]byte, 4)
	NativeEndian.PutUint32(b, v)
	return
}

// WriteUint64 writes the provided uint64 value to byte slice.
func WriteUint64(v uint64) (b []byte) {
	b = make([]byte, 8)
	NativeEndian.PutUint64(b, v)
	return
}
