/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package params

import (
	"math"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// Kind is the discriminator of the Value tagged union. It describes the
// physical representation of the stored value, as opposed to Type which
// describes its logical meaning (e.g. PID, Port, Address are all KindUint).
type Kind uint8

const (
	// KindNull designates an absent value.
	KindNull Kind = iota
	// KindUint is an unsigned integer of up to 64 bits. Also used for
	// addresses, identifiers, ports, flags, enums and status codes.
	KindUint
	// KindInt is a signed integer of up to 64 bits.
	KindInt
	// KindBool is a boolean.
	KindBool
	// KindFloat is an IEEE 754 floating-point number (32 or 64 bits).
	KindFloat
	// KindTime is a timestamp stored as Unix nanoseconds.
	KindTime
	// KindString is a string.
	KindString
	// KindBytes is an opaque byte buffer (binary data, SIDs).
	KindBytes
	// KindIP is an IPv4 or IPv6 address.
	KindIP
	// KindUintSlice is a slice of 64-bit unsigned integers (e.g. call stack return addresses).
	KindUintSlice
	// KindStringSlice is a slice of strings.
	KindStringSlice
)

// Value is a tagged union that stores event parameter values without
// boxing them into an interface. It occupies 24 bytes:
//
//	| kind | bits | num (8) | ptr (8) |
//
// Scalars live entirely in num. Variable-sized kinds keep the data pointer
// in ptr and the element count in num. The pointer is an unsafe.Pointer, so
// the garbage collector keeps the referenced memory alive.
//
// The zero Value is KindNull.
type Value struct {
	ptr  unsafe.Pointer
	num  uint64
	kind Kind
	// bits is the width of the numeric kinds (8, 16, 32, 64). For
	// KindIP it is 4 for IPv4, and 16 for IPv6 addresses.
	bits uint8
}

// U8 creates an unsigned 8-bit integer value.
func U8(v uint8) Value { return Value{kind: KindUint, bits: 8, num: uint64(v)} }

// U16 creates an unsigned 16-bit integer value.
func U16(v uint16) Value { return Value{kind: KindUint, bits: 16, num: uint64(v)} }

// U32 creates an unsigned 32-bit integer value.
func U32(v uint32) Value { return Value{kind: KindUint, bits: 32, num: uint64(v)} }

// U64 creates an unsigned 64-bit integer value.
func U64(v uint64) Value { return Value{kind: KindUint, bits: 64, num: v} }

// I8 creates a signed 8-bit integer value.
func I8(v int8) Value { return Value{kind: KindInt, bits: 8, num: uint64(int64(v))} }

// I16 creates a signed 16-bit integer value.
func I16(v int16) Value { return Value{kind: KindInt, bits: 16, num: uint64(int64(v))} }

// I32 creates a signed 32-bit integer value.
func I32(v int32) Value { return Value{kind: KindInt, bits: 32, num: uint64(int64(v))} }

// I64 creates a signed 64-bit integer value.
func I64(v int64) Value { return Value{kind: KindInt, bits: 64, num: uint64(v)} }

// Boolean creates a boolean value.
func Boolean(v bool) Value {
	if v {
		return Value{kind: KindBool, bits: 8, num: 1}
	}
	return Value{kind: KindBool, bits: 8}
}

// F32 creates a 32-bit floating-point value.
func F32(v float32) Value {
	return Value{kind: KindFloat, bits: 32, num: uint64(math.Float32bits(v))}
}

// F64 creates a 64-bit floating-point value.
func F64(v float64) Value { return Value{kind: KindFloat, bits: 64, num: math.Float64bits(v)} }

// Timestamp creates a timestamp value. The time is stored with nanosecond
// precision as the offset from the Unix epoch. The monotonic clock reading
// and the location are not preserved.
func Timestamp(t time.Time) Value {
	return Value{kind: KindTime, bits: 64, num: uint64(t.UnixNano())}
}

// Str creates a string value.
func Str(s string) Value {
	return Value{kind: KindString, ptr: unsafe.Pointer(unsafe.StringData(s)), num: uint64(len(s))}
}

// Bin creates a binary value. The buffer is not copied. It is the
// responsibility of the caller to hand over ownership of the buffer.
func Bin(b []byte) Value {
	return Value{kind: KindBytes, ptr: unsafe.Pointer(unsafe.SliceData(b)), num: uint64(len(b))}
}

// IPv4LE creates an IPv4 address value from the 32-bit integer that
// was read from a little-endian buffer holding the address in network
// byte order. That is, the first octet resides in the low-order byte.
func IPv4LE(v uint32) Value {
	return IP4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// IP4 creates an IPv4 address value from its four octets.
func IP4(a, b, c, d byte) Value {
	return Value{kind: KindIP, bits: 4, num: uint64(a)<<24 | uint64(b)<<16 | uint64(c)<<8 | uint64(d)}
}

// IP6 creates an IPv6 address value. The buffer must be at least 16 bytes
// long, and its content is copied into a new allocation.
func IP6(b []byte) Value {
	if len(b) < 16 {
		return Value{}
	}
	a := new([16]byte)
	copy(a[:], b)
	return Value{kind: KindIP, bits: 16, ptr: unsafe.Pointer(a)}
}

// IPAddr creates an address value from the net.IP. The IPv4 and
// IPv4-mapped IPv6 addresses are stored as IPv4. Invalid addresses
// yield the null value.
func IPAddr(ip net.IP) Value {
	if v4 := ip.To4(); v4 != nil {
		return IP4(v4[0], v4[1], v4[2], v4[3])
	}
	if len(ip) == net.IPv6len {
		return IP6(ip)
	}
	return Value{}
}

// U64Slice creates a value that holds a slice of unsigned 64-bit integers.
// The slice is not copied.
func U64Slice(s []uint64) Value {
	return Value{kind: KindUintSlice, bits: 64, ptr: unsafe.Pointer(unsafe.SliceData(s)), num: uint64(len(s))}
}

// StrSlice creates a value that holds a slice of strings. The slice is not copied.
func StrSlice(s []string) Value {
	return Value{kind: KindStringSlice, ptr: unsafe.Pointer(unsafe.SliceData(s)), num: uint64(len(s))}
}

// Addresses creates the parameter value from the slice of addresses. The slice is not copied.
func Addresses(addrs []va.Address) Value {
	return U64Slice(unsafe.Slice((*uint64)(unsafe.Pointer(unsafe.SliceData(addrs))), len(addrs)))
}

// Kind returns the discriminator of the union.
func (v Value) Kind() Kind { return v.kind }

// Bits returns the width of the numeric kinds.
func (v Value) Bits() uint8 { return v.bits }

// IsNull indicates if the value is absent.
func (v Value) IsNull() bool { return v.kind == KindNull }

func (v Value) isInteger() bool {
	return v.kind == KindUint || v.kind == KindInt || v.kind == KindBool
}

// Uint64 returns the integer value as uint64. Zero is returned for non-integer kinds.
func (v Value) Uint64() uint64 {
	if v.isInteger() {
		return v.num
	}
	return 0
}

// Uint32 returns the integer value truncated to uint32.
func (v Value) Uint32() uint32 { return uint32(v.Uint64()) }

// Uint16 returns the integer value truncated to uint16.
func (v Value) Uint16() uint16 { return uint16(v.Uint64()) }

// Uint8 returns the integer value truncated to uint8.
func (v Value) Uint8() uint8 { return uint8(v.Uint64()) }

// Int64 returns the integer value as int64.
func (v Value) Int64() int64 { return int64(v.Uint64()) }

// Int32 returns the integer value truncated to int32.
func (v Value) Int32() int32 { return int32(v.Uint64()) }

// Int16 returns the integer value truncated to int16.
func (v Value) Int16() int16 { return int16(v.Uint64()) }

// Int8 returns the integer value truncated to int8.
func (v Value) Int8() int8 { return int8(v.Uint64()) }

// Bool returns the boolean value. It is false for all non-boolean kinds.
func (v Value) Bool() bool { return v.kind == KindBool && v.num != 0 }

// Float64 returns the floating-point value as float64.
func (v Value) Float64() float64 {
	if v.kind != KindFloat {
		return 0
	}
	if v.bits == 32 {
		return float64(math.Float32frombits(uint32(v.num)))
	}
	return math.Float64frombits(v.num)
}

// Float32 returns the floating-point value as float32.
func (v Value) Float32() float32 { return float32(v.Float64()) }

// Time returns the timestamp. The Unix epoch is returned for non-time kinds.
func (v Value) Time() time.Time {
	if v.kind != KindTime {
		return time.Unix(0, 0)
	}
	return time.Unix(0, int64(v.num))
}

// Str returns the string. It is empty for non-string kinds.
func (v Value) Str() string {
	if v.kind != KindString || v.num == 0 {
		return ""
	}
	return unsafe.String((*byte)(v.ptr), int(v.num))
}

// Bytes returns the binary buffer. It is nil for non-binary kinds.
func (v Value) Bytes() []byte {
	if v.kind != KindBytes {
		return nil
	}
	return unsafe.Slice((*byte)(v.ptr), int(v.num))
}

// IP returns the IP address. It is nil for non-IP kinds. The
// IPv4 addresses are returned in the 16-byte form, like net.IPv4 does.
func (v Value) IP() net.IP {
	if v.kind != KindIP {
		return nil
	}
	if v.bits == 4 {
		return net.IPv4(byte(v.num>>24), byte(v.num>>16), byte(v.num>>8), byte(v.num))
	}
	return net.IP(unsafe.Slice((*byte)(v.ptr), 16)[:16:16])
}

// IsIPv4 indicates if the value is an IPv4 address.
func (v Value) IsIPv4() bool { return v.kind == KindIP && v.bits == 4 }

// IsIPv6 indicates if the value is an IPv6 address.
func (v Value) IsIPv6() bool { return v.kind == KindIP && v.bits == 16 }

// U64Slice returns the slice of integers. It is nil for non-slice kinds.
func (v Value) U64Slice() []uint64 {
	if v.kind != KindUintSlice || v.ptr == nil {
		return nil
	}
	return unsafe.Slice((*uint64)(v.ptr), int(v.num))
}

// StrSlice returns the slice of strings. It is nil for non-slice kinds.
func (v Value) StrSlice() []string {
	if v.kind != KindStringSlice || v.ptr == nil {
		return nil
	}
	return unsafe.Slice((*string)(v.ptr), int(v.num))
}

// IsSlice indicates if the value holds a slice.
func (v Value) IsSlice() bool { return v.kind == KindUintSlice || v.kind == KindStringSlice }

// Len returns the number of elements for slices, strings and binary values.
func (v Value) Len() int {
	switch v.kind {
	case KindString, KindBytes, KindUintSlice, KindStringSlice:
		return int(v.num)
	}
	return 0
}

// String renders the value according to its kind. It is the fallback for
// the types that don't have a dedicated representation.
func (v *Value) String() string {
	switch v.Kind() {
	case KindUint:
		return strconv.FormatUint(v.Uint64(), 10)
	case KindInt:
		return strconv.FormatInt(v.Int64(), 10)
	case KindBool:
		return strconv.FormatBool(v.Bool())
	case KindFloat:
		if v.Bits() == 32 {
			return strconv.FormatFloat(v.Float64(), 'f', 6, 32)
		}
		return strconv.FormatFloat(v.Float64(), 'f', 6, 64)
	case KindTime:
		return v.Time().String()
	case KindString:
		return v.Str()
	case KindBytes:
		return string(v.Bytes())
	case KindIP:
		return v.IP().String()
	case KindUintSlice:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, n := range v.U64Slice() {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(strconv.FormatUint(n, 10))
		}
		sb.WriteByte(']')
		return sb.String()
	case KindStringSlice:
		return strings.Join(v.StrSlice(), ",")
	default:
		return ""
	}
}

// TypeFromKind derives the type of the parameter from the kind of the stored value.
func (v Value) ParamType() Type {
	switch v.Kind() {
	case KindUint:
		switch v.Bits() {
		case 8:
			return Uint8
		case 16:
			return Uint16
		case 32:
			return Uint32
		}
		return Uint64
	case KindInt:
		switch v.Bits() {
		case 8:
			return Int8
		case 16:
			return Int16
		case 32:
			return Int32
		}
		return Int64
	case KindBool:
		return Bool
	case KindFloat:
		if v.Bits() == 32 {
			return Float
		}
		return Double
	case KindTime:
		return Time
	case KindString:
		return String
	case KindBytes:
		return Binary
	case KindIP:
		return IP
	case KindUintSlice, KindStringSlice:
		return Slice
	default:
		return Null
	}
}
