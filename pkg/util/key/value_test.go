//go:build windows
// +build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package key

import (
	"encoding/binary"
	"slices"
	"testing"
	"unicode/utf16"
)

// encMultiSZ builds a well-formed REG_MULTI_SZ buffer: every string is
// followed by a NUL, and the list ends with an extra NUL.
func encMultiSZ(terminated bool, strs ...string) []byte {
	var b []byte
	for _, s := range strs {
		for _, u := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
		b = binary.LittleEndian.AppendUint16(b, 0)
	}
	if terminated {
		b = binary.LittleEndian.AppendUint16(b, 0)
	}
	return b
}

func TestMultiSZ(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []string
	}{
		{"nil buffer", nil, nil},
		{"empty buffer", []byte{}, nil},
		{"single odd byte", []byte{0x61}, nil},
		{"only double NUL", []byte{0, 0, 0, 0}, nil},
		{"single NUL", []byte{0, 0}, nil},
		{
			"one string",
			encMultiSZ(true, "hello"),
			[]string{"hello"},
		},
		{
			"several strings",
			encMultiSZ(true, "alpha", "beta", "gamma"),
			[]string{"alpha", "beta", "gamma"},
		},
		{
			"single terminator only",
			encMultiSZ(false, "alpha", "beta"),
			[]string{"alpha", "beta"},
		},
		{
			"no terminator at all",
			// "a\0b" with the final NUL missing
			[]byte{0x61, 0, 0, 0, 0x62, 0},
			[]string{"a", "b"},
		},
		{
			"trailing odd byte is dropped",
			append(encMultiSZ(true, "abc"), 0x41),
			[]string{"abc"},
		},
		{
			"data after the terminator is ignored",
			// "a\0\0b" : the list ends at the double NUL
			[]byte{0x61, 0, 0, 0, 0, 0, 0x62, 0},
			[]string{"a"},
		},
		{
			"non-ASCII BMP characters",
			encMultiSZ(true, "größe", "路径"),
			[]string{"größe", "路径"},
		},
		{
			"surrogate pair",
			encMultiSZ(true, "😀", "ok"),
			[]string{"😀", "ok"},
		},
		{
			"unpaired surrogate becomes replacement char",
			// 0xD800 followed by the terminators
			[]byte{0x00, 0xD8, 0, 0, 0, 0},
			[]string{"\uFFFD"},
		},
		{
			"windows paths",
			encMultiSZ(true, `C:\Windows\System32`, `C:\Program Files`),
			[]string{`C:\Windows\System32`, `C:\Program Files`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MultiSZ(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Errorf("multiSZ(% x)\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUint(t *testing.T) {
	tests := []struct {
		name  string
		in    []byte
		order binary.ByteOrder
		want  uint64
	}{
		{"nil", nil, binary.LittleEndian, 0},
		{"empty", []byte{}, binary.BigEndian, 0},
		{"1 byte LE", []byte{0x7f}, binary.LittleEndian, 0x7f},
		{"1 byte BE", []byte{0x7f}, binary.BigEndian, 0x7f},
		{"2 bytes LE", []byte{0x01, 0x02}, binary.LittleEndian, 0x0201},
		{"2 bytes BE", []byte{0x01, 0x02}, binary.BigEndian, 0x0102},
		{"4 bytes LE", []byte{1, 2, 3, 4}, binary.LittleEndian, 0x04030201},
		{"4 bytes BE", []byte{1, 2, 3, 4}, binary.BigEndian, 0x01020304},
		{"8 bytes LE", []byte{1, 2, 3, 4, 5, 6, 7, 8}, binary.LittleEndian, 0x0807060504030201},
		{"8 bytes BE", []byte{1, 2, 3, 4, 5, 6, 7, 8}, binary.BigEndian, 0x0102030405060708},
		{"max uint32 LE", []byte{0xff, 0xff, 0xff, 0xff}, binary.LittleEndian, 0xffffffff},
		{"max uint64 BE", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, binary.BigEndian, 0xffffffffffffffff},
		{"3 bytes unsupported", []byte{1, 2, 3}, binary.LittleEndian, 0},
		{"5 bytes unsupported", []byte{1, 2, 3, 4, 5}, binary.BigEndian, 0},
		{"9 bytes unsupported", make([]byte, 9), binary.LittleEndian, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Uint(tt.in, tt.order); got != tt.want {
				t.Errorf("readUint(% x) = %#x, want %#x", tt.in, got, tt.want)
			}
		})
	}
}
