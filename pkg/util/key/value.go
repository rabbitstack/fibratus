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
	"unicode/utf16"
)

// MultiSZ decodes a REG_MULTI_SZ buffer into its component strings.
// The format is: str1\0str2\0...strN\0\0
func MultiSZ(b []byte) []string {
	n := len(b) / 2
	if n == 0 {
		return nil
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	var out []string
	start := 0
	for i, c := range u {
		if c != 0 {
			continue
		}
		if i == start {
			return out // empty element signals the end of list

		}
		out = append(out, string(utf16.Decode(u[start:i])))
		start = i + 1
	}
	// keep the unterminated tail
	if start < n {
		out = append(out, string(utf16.Decode(u[start:])))
	}
	return out
}

// Uint decodes the REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD from the
// byte slice according to the byte order.
func Uint(b []byte, order binary.ByteOrder) uint64 {
	switch len(b) {
	case 8:
		return order.Uint64(b)
	case 4:
		return uint64(order.Uint32(b))
	case 2:
		return uint64(order.Uint16(b))
	case 1:
		return uint64(b[0])
	}
	return 0
}
