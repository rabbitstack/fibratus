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

package kparams

import (
	"strconv"
)

const (
	// NA defines absent parameter's value
	NA = "na"
)

// Value defines the container for parameter values
type Value interface{}

// Type defines kernel event parameter type
type Type uint16

// Hex is the type alias for hexadecimal values
type Hex string

// NewHex creates a new Hex type from the given integer value.
func NewHex(v Value) Hex {
	switch n := v.(type) {
	case uint8:
		return Hex(strconv.FormatUint(uint64(n), 16))
	case uint16:
		return Hex(strconv.FormatUint(uint64(n), 16))
	case uint32:
		return Hex(strconv.FormatUint(uint64(n), 16))
	case uint64:
		return Hex(strconv.FormatUint(uint64(n), 16))
	case int32:
		return Hex(strconv.FormatInt(int64(n), 16))
	case int64:
		return Hex(strconv.FormatInt(int64(n), 16))
	default:
		return ""
	}
}

// Uint8 yields an uint8 value from its hex representation.
func (hex Hex) Uint8() uint8 { return uint8(hex.parseUint(8)) }

// Uint16 yields an uint16 value from its hex representation.
func (hex Hex) Uint16() uint16 { return uint16(hex.parseUint(16)) }

// Uint32 yields an uint32 value from its hex representation.
func (hex Hex) Uint32() uint32 { return uint32(hex.parseUint(32)) }

// Uint64 yields an uint64 value from its hex representation.
func (hex Hex) Uint64() uint64 { return hex.parseUint(64) }

func (hex Hex) parseUint(bitSize int) uint64 {
	num, err := strconv.ParseUint(string(hex), 16, bitSize)
	if err != nil {
		return uint64(0)
	}
	return num
}

// String returns a string representation of the hex value.
func (hex Hex) String() string {
	return string(hex)
}

const (
	Null Type = iota
	UnicodeString
	AnsiString
	Int8
	Uint8
	Int16
	Uint16
	Int32
	Uint32
	Int64
	Uint64
	Float
	Double
	Bool
	Binary
	GUID
	Pointer
	SID
	PID
	TID
	WbemSID
	HexInt8
	HexInt16
	HexInt32
	HexInt64
	Port
	IP
	IPv4
	IPv6
	Time  // timestamp
	Slice // sequence of values
	Enum  // enumeration
	Map
	Object
	Unknown
)

func (t Type) String() string {
	switch t {
	case UnicodeString:
		return "unicode"
	case AnsiString:
		return "ansi"
	case Int8:
		return "int8"
	case Uint8:
		return "uint8"
	case HexInt8:
		return "hex8"
	case Int16:
		return "int16"
	case Uint16:
		return "uint16"
	case HexInt16:
		return "hex16"
	case Int32:
		return "int32"
	case Uint32:
		return "uint32"
	case Int64:
		return "int64"
	case Uint64:
		return "uint64"
	case HexInt32:
		return "hex32"
	case HexInt64:
		return "hex64"
	case SID, WbemSID:
		return "sid"
	case TID:
		return "tid"
	case PID:
		return "pid"
	case Port:
		return "port"
	case IPv6:
		return "ipv6"
	case IPv4:
		return "ipv4"
	default:
		return "unknown"
	}
}
