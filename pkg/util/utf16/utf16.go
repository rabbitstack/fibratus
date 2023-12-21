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

// Decode decodes the UTF16-encoded string to UTF-8 string. This function
// exhibits much better performance than the standard library counterpart.
// All credits go to: https://gist.github.com/skeeto/09f1410183d246f9b18cba95c4e602f0
func Decode(p []uint16) string {
	s := make([]byte, 0, 2*len(p))
	for i := 0; i < len(p); i++ {
		r := rune(0xfffd)
		r1 := rune(p[i])
		if isHighSurrogate(r1) {
			if i+1 < len(p) {
				r2 := rune(p[i+1])
				if isLowSurrogate(r2) {
					i++
					r = 0x10000 + (r1-surr1)<<10 + (r2 - surr2)
				}
			}
		} else if !isLowSurrogate(r) {
			r = r1
		}
		s = utf8.AppendRune(s, r)
	}
	return string(s)
}
