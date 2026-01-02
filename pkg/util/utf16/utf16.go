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

package utf16

import (
	"encoding/binary"
	"unicode/utf8"
)

const (
	// 0xd800-0xdc00 encodes the high 10 bits of a pair.
	surr1 = 0xd800
	// 0xdc00-0xe000 encodes the low 10 bits of a pair.
	surr2 = 0xdc00
)

func isHighSurrogate(r rune) bool { return r >= surr1 && r <= 0xdbff }
func isLowSurrogate(r rune) bool  { return r >= surr2 && r <= 0xdfff }

// Decode decodes the UTF16-encoded string to UTF-8 string using fast ASCII path.
// This function exhibits much better performance than the standard library counterpart.
func Decode(p []uint16) string {
	n := len(p)
	if n == 0 {
		return ""
	}

	s := make([]byte, 0, n*2)

	for i := 0; i < len(p); i++ {
		// ascii fast-path (0x0000–0x007F)
		if p[i] <= 0x7F {
			s = append(s, byte(p[i]))
			continue
		}

		r1 := rune(p[i])

		// surrogate pair handling
		if isHighSurrogate(r1) && i+1 < n {
			r2 := rune(p[i+1])
			if isLowSurrogate(r2) {
				i++
				r := 0x10000 + (r1-surr1)<<10 + (r2 - surr2)
				s = utf8.AppendRune(s, r)
				continue
			}
		}

		// non-surrogate BMP code point or malformed surrogate
		if !isLowSurrogate(r1) {
			s = utf8.AppendRune(s, r1)
		} else {
			// lone low surrogate to replacement char
			s = utf8.AppendRune(s, utf8.RuneError)
		}
	}

	return string(s)
}

// BytesToString converts the UTF16-encoded byte buffer to string.
func BytesToString(b []byte, o binary.ByteOrder) string {
	utf := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := o.Uint16(b[i:])
		if u == 0 {
			break // stop at null terminator
		}
		utf = append(utf, u)
	}
	return Decode(utf)
}
