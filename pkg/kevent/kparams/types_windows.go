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
	case int32:
		return Hex(strconv.FormatInt(int64(n), 16))
	case uint64:
		return Hex(strconv.FormatUint(n, 16))
	case int64:
		return Hex(strconv.FormatInt(n, 16))
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
	// Null is a null parameter type
	Null Type = iota
	// UnicodeString a string of 16-bit characters. By default, assumed to have been encoded using UTF-16LE
	UnicodeString
	// AnsiString a string of 8-bit characters
	AnsiString
	// Int8 a signed 8-bit integer
	Int8
	// Uint8 an unsigned 8-bit integer
	Uint8
	// Int16 a signed 16-bit integer
	Int16
	// Uint16 an unsigned 16-bit integer
	Uint16
	// Int32 a signed 32-bit integer
	Int32
	// Uint32 an unsigned 32-bit integer
	Uint32
	// Int64 a signed 64-bit integer
	Int64
	// Uint64 an unsigned 64-bit integer
	Uint64
	// Float an IEEE 4-byte floating-point number
	Float
	// Double an IEEE 8-byte floating-point number
	Double
	// Bool a 32-bit value where 0 is false and 1 is true
	Bool
	// Binary is a binary data of variable size. The size must be specified in the data definition as a constant or a reference to another (integer) data item.For an IP V6 address, the data should be an IN6_ADDR structure.
	// For a socket address, the data should be a SOCKADDR_STORAGE structure. The AF_INET, AF_INET6, and AF_LINK address families are supported
	Binary
	// GUID is a GUID structure. On output, the GUID is rendered in the registry string form, {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
	GUID
	// Pointer an unsigned 32-bit or 64-bit pointer value. The size depends on the architecture of the computer logging the event
	Pointer
	// SID a security identifier (SID) structure that uniquely identifies a user or group
	SID
	// PID is the process identifier
	PID
	// TID is the thread identifier
	TID
	// WbemSID is the Web-Based Enterprise Management security identifier.
	WbemSID
	// HexInt8 is the hexadecimal representation of 8-bit integer
	HexInt8
	// HexInt16 is the hexadecimal representation of 16-bit integer
	HexInt16
	// HexInt32 is the hexadecimal representation of 32-bit integer
	HexInt32
	// HexInt64 is the hexadecimal representation of 64-bit integer
	HexInt64
	// Port represents the endpoint port number
	Port
	// IP is the IP address
	IP
	// IPv4 is the IPv4 address
	IPv4
	// IPv6 is the IPv6 address
	IPv6
	// Time represents the timestamp
	Time
	// Slice represents a collection of items
	Slice
	// Enum represents an enumeration
	Enum
	// Map represents a map
	Map
	// Object is the generic object type
	Object
	// FileDosPath represents the file system path in DOS device notation
	FileDosPath
	// FilePath represents the file system path with normalized drive letter notation
	FilePath
	// Status represents the system error code message
	Status
	// Key represents the registry key
	Key
	// Flags represents a bitmask of flags
	Flags
	// Address is the memory address reference
	Address
	// HandleType represents the handle type such as Mutex or File
	HandleType
)

// String return the type string representation.
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
