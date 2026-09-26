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

package event

import (
	"math"
	"strconv"
	"unicode/utf8"
)

type jsonStream struct {
	buf []byte
}

func newJSONStream() *jsonStream {
	return &jsonStream{buf: make([]byte, 0)}
}

func (js *jsonStream) flush() []byte {
	buf := js.buf
	js.buf = nil
	return buf
}

func (js *jsonStream) writeByte(c byte) {
	js.buf = append(js.buf, c)
}

func (js *jsonStream) writeTwoBytes(c1, c2 byte) {
	js.buf = append(js.buf, c1, c2)
}

func (js *jsonStream) writeString(s string) *jsonStream {
	js.writeByte('"')
	js.buf = append(js.buf, s...)
	js.writeByte('"')
	return js
}

func (js *jsonStream) writeRaw(s string) {
	js.buf = append(js.buf, s...)
}

func (js *jsonStream) writeEscapeString(s string) *jsonStream {
	valLen := len(s)
	js.buf = append(js.buf, '"')
	// write string, the fast path, without utf8 and escape support
	i := 0
	for ; i < valLen; i++ {
		c := s[i]
		if c > 31 && c != '"' && c != '\\' {
			js.buf = append(js.buf, c)
		} else {
			break
		}
	}
	if i == valLen {
		js.buf = append(js.buf, '"')
		return js
	}

	// write remaining part of the string with escape support
	writeStringSlowPath(js, i, s, valLen)
	return js
}

//nolint:unparam
func (js *jsonStream) writeObjectStart() *jsonStream {
	js.writeByte('{')
	return js
}

//nolint:unparam
func (js *jsonStream) writeArrayStart() *jsonStream {
	js.writeByte('[')
	return js
}

func (js *jsonStream) writeArrayEnd() *jsonStream {
	js.writeByte(']')
	return js
}

func (js *jsonStream) writeObjectField(f string) *jsonStream {
	js.writeString(f)
	js.writeTwoBytes(':', ' ')
	return js
}

func (js *jsonStream) writeBool(b bool) *jsonStream {
	if b {
		js.writeString("true")
		return js
	}
	js.writeString("false")
	return js
}

func (js *jsonStream) writeObjectEnd() *jsonStream {
	js.writeByte('}')
	return js
}

//nolint:unparam
func (js *jsonStream) writeMore() *jsonStream {
	js.writeByte(',')
	return js
}

func (js *jsonStream) shouldWriteMore(i, l int) bool {
	//nolint:staticcheck
	return !(i == l-1)
}

// borrowed from jsointer: https://github.com/json-iterator/go/blob/2fbdfbb5951116fb8bede4fd8b919a19e4a6b647/stream_int.go and https://github.com/json-iterator/go/blob/2fbdfbb5951116fb8bede4fd8b919a19e4a6b647/stream_float.go

var digits []uint32

// safeSet holds the value true if the ASCII character with the given array
// position can be represented inside a JSON string without any further
// escaping.
//
// All values are true except for the ASCII control characters (0-31), the
// double quote ("), and the backslash character ("\").
var safeSet = [utf8.RuneSelf]bool{
	' ':      true,
	'!':      true,
	'"':      false,
	'#':      true,
	'$':      true,
	'%':      true,
	'&':      true,
	'\'':     true,
	'(':      true,
	')':      true,
	'*':      true,
	'+':      true,
	',':      true,
	'-':      true,
	'.':      true,
	'/':      true,
	'0':      true,
	'1':      true,
	'2':      true,
	'3':      true,
	'4':      true,
	'5':      true,
	'6':      true,
	'7':      true,
	'8':      true,
	'9':      true,
	':':      true,
	';':      true,
	'<':      true,
	'=':      true,
	'>':      true,
	'?':      true,
	'@':      true,
	'A':      true,
	'B':      true,
	'C':      true,
	'D':      true,
	'E':      true,
	'F':      true,
	'G':      true,
	'H':      true,
	'I':      true,
	'J':      true,
	'K':      true,
	'L':      true,
	'M':      true,
	'N':      true,
	'O':      true,
	'P':      true,
	'Q':      true,
	'R':      true,
	'S':      true,
	'T':      true,
	'U':      true,
	'V':      true,
	'W':      true,
	'X':      true,
	'Y':      true,
	'Z':      true,
	'[':      true,
	'\\':     false,
	']':      true,
	'^':      true,
	'_':      true,
	'`':      true,
	'a':      true,
	'b':      true,
	'c':      true,
	'd':      true,
	'e':      true,
	'f':      true,
	'g':      true,
	'h':      true,
	'i':      true,
	'j':      true,
	'k':      true,
	'l':      true,
	'm':      true,
	'n':      true,
	'o':      true,
	'p':      true,
	'q':      true,
	'r':      true,
	's':      true,
	't':      true,
	'u':      true,
	'v':      true,
	'w':      true,
	'x':      true,
	'y':      true,
	'z':      true,
	'{':      true,
	'|':      true,
	'}':      true,
	'~':      true,
	'\u007f': true,
}

var hex = "0123456789abcdef"

func init() {
	digits = make([]uint32, 1000)
	for i := uint32(0); i < 1000; i++ {
		digits[i] = (((i / 100) + '0') << 16) + ((((i / 10) % 10) + '0') << 8) + i%10 + '0'
		if i < 10 {
			digits[i] += 2 << 24
		} else if i < 100 {
			digits[i] += 1 << 24
		}
	}
}

func writeStringSlowPath(stream *jsonStream, i int, s string, valLen int) {
	start := i
	// for the remaining parts, we process them char by char
	for i < valLen {
		if b := s[i]; b < utf8.RuneSelf {
			if safeSet[b] {
				i++
				continue
			}
			if start < i {
				stream.writeRaw(s[start:i])
			}
			switch b {
			case '\\', '"':
				stream.writeTwoBytes('\\', b)
			case '\n':
				stream.writeTwoBytes('\\', 'n')
			case '\r':
				stream.writeTwoBytes('\\', 'r')
			case '\t':
				stream.writeTwoBytes('\\', 't')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				stream.writeRaw(`\u00`)
				stream.writeTwoBytes(hex[b>>4], hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		i++
		continue
	}
	if start < len(s) {
		stream.writeRaw(s[start:])
	}
	stream.writeByte('"')
}

func writeFirstBuf(space []byte, v uint32) []byte {
	start := v >> 24
	switch start {
	case 0:
		space = append(space, byte(v>>16), byte(v>>8))
	case 1:
		space = append(space, byte(v>>8))
	}
	space = append(space, byte(v))
	return space
}

func writeBuf(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>16), byte(v>>8), byte(v))
}

func (js *jsonStream) writeUint8(val uint8) *jsonStream {
	js.buf = writeFirstBuf(js.buf, digits[val])
	return js
}

func (js *jsonStream) writeInt8(nval int8) *jsonStream {
	var val uint8
	if nval < 0 {
		val = uint8(-nval)
		js.buf = append(js.buf, '-')
	} else {
		val = uint8(nval)
	}
	js.buf = writeFirstBuf(js.buf, digits[val])
	return js
}

func (js *jsonStream) writeUint16(val uint16) *jsonStream {
	q1 := val / 1000
	if q1 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[val])
		return js
	}
	r1 := val - q1*1000
	js.buf = writeFirstBuf(js.buf, digits[q1])
	js.buf = writeBuf(js.buf, digits[r1])
	return js
}

func (js *jsonStream) writeInt16(nval int16) *jsonStream {
	var val uint16
	if nval < 0 {
		val = uint16(-nval)
		js.buf = append(js.buf, '-')
	} else {
		val = uint16(nval)
	}
	js.writeUint16(val)
	return js
}

func (js *jsonStream) writeUint32(val uint32) *jsonStream {
	q1 := val / 1000
	if q1 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[val])
		return js
	}
	r1 := val - q1*1000
	q2 := q1 / 1000
	if q2 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q1])
		js.buf = writeBuf(js.buf, digits[r1])
		return js
	}
	r2 := q1 - q2*1000
	q3 := q2 / 1000
	if q3 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q2])
	} else {
		r3 := q2 - q3*1000
		js.buf = append(js.buf, byte(q3+'0'))
		js.buf = writeBuf(js.buf, digits[r3])
	}
	js.buf = writeBuf(js.buf, digits[r2])
	js.buf = writeBuf(js.buf, digits[r1])
	return js
}

func (js *jsonStream) writeInt32(nval int32) *jsonStream {
	var val uint32
	if nval < 0 {
		val = uint32(-nval)
		js.buf = append(js.buf, '-')
	} else {
		val = uint32(nval)
	}
	js.writeUint32(val)
	return js
}

func (js *jsonStream) writeUint64(val uint64) *jsonStream {
	q1 := val / 1000
	if q1 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[val])
		return js
	}
	r1 := val - q1*1000
	q2 := q1 / 1000
	if q2 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q1])
		js.buf = writeBuf(js.buf, digits[r1])
		return js
	}
	r2 := q1 - q2*1000
	q3 := q2 / 1000
	if q3 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q2])
		js.buf = writeBuf(js.buf, digits[r2])
		js.buf = writeBuf(js.buf, digits[r1])
		return js
	}
	r3 := q2 - q3*1000
	q4 := q3 / 1000
	if q4 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q3])
		js.buf = writeBuf(js.buf, digits[r3])
		js.buf = writeBuf(js.buf, digits[r2])
		js.buf = writeBuf(js.buf, digits[r1])
		return js
	}
	r4 := q3 - q4*1000
	q5 := q4 / 1000
	if q5 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q4])
		js.buf = writeBuf(js.buf, digits[r4])
		js.buf = writeBuf(js.buf, digits[r3])
		js.buf = writeBuf(js.buf, digits[r2])
		js.buf = writeBuf(js.buf, digits[r1])
		return js
	}
	r5 := q4 - q5*1000
	q6 := q5 / 1000
	if q6 == 0 {
		js.buf = writeFirstBuf(js.buf, digits[q5])
	} else {
		js.buf = writeFirstBuf(js.buf, digits[q6])
		r6 := q5 - q6*1000
		js.buf = writeBuf(js.buf, digits[r6])
	}
	js.buf = writeBuf(js.buf, digits[r5])
	js.buf = writeBuf(js.buf, digits[r4])
	js.buf = writeBuf(js.buf, digits[r3])
	js.buf = writeBuf(js.buf, digits[r2])
	js.buf = writeBuf(js.buf, digits[r1])
	return js
}

func (js *jsonStream) writeInt64(nval int64) *jsonStream {
	var val uint64
	if nval < 0 {
		val = uint64(-nval)
		js.buf = append(js.buf, '-')
	} else {
		val = uint64(nval)
	}
	js.writeUint64(val)
	return js
}

// writeFloat32 write float32 to stream
func (js *jsonStream) writeFloat32(val float32) *jsonStream {
	abs := math.Abs(float64(val))
	format := byte('f')
	// Note: Must use float32 comparisons for underlying float32 value to get precise cutoffs right.
	if abs != 0 {
		if float32(abs) < 1e-6 || float32(abs) >= 1e21 {
			format = 'e'
		}
	}
	js.buf = strconv.AppendFloat(js.buf, float64(val), format, -1, 32)
	return js
}

// writeFloat64 write float64 to stream
func (js *jsonStream) writeFloat64(val float64) *jsonStream {
	abs := math.Abs(val)
	format := byte('f')
	// Note: Must use float32 comparisons for underlying float32 value to get precise cutoffs right.
	if abs != 0 {
		if abs < 1e-6 || abs >= 1e21 {
			format = 'e'
		}
	}
	js.buf = strconv.AppendFloat(js.buf, val, format, -1, 64)
	return js
}
