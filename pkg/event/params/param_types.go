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

// Type defines an event parameter type.
type Type uint16

const (
	// Null is a null parameter type.
	Null Type = 0
	// Int8 is a signed 8-bit integer.
	Int8 Type = 3
	// Uint8 is an unsigned 8-bit integer.
	Uint8 Type = 4
	// Int16 is a signed 16-bit integer.
	Int16 Type = 5
	// Uint16 is an unsigned 16-bit integer.
	Uint16 Type = 6
	// Int32 is a signed 32-bit integer.
	Int32 Type = 7
	// Uint32 is an unsigned 32-bit integer.
	Uint32 Type = 8
	// Int64 is a signed 64-bit integer.
	Int64 Type = 9
	// Uint64 is an unsigned 64-bit integer.
	Uint64 Type = 10
	// Float is an IEEE 4-byte floating-point number.
	Float Type = 11
	// Double is an IEEE 8-byte floating-point number.
	Double Type = 12
	// Bool is a boolean value.
	Bool Type = 13
	// Binary is variable-sized binary data.
	Binary Type = 14
	// PID is a process identifier.
	PID Type = 18
	// TID is a thread identifier.
	TID Type = 19
	// Port is an endpoint port number.
	Port Type = 21
	// IP is an IP address.
	IP Type = 22
	// IPv4 is an IPv4 address.
	IPv4 Type = 23
	// IPv6 is an IPv6 address.
	IPv6 Type = 24
	// Time is a timestamp.
	Time Type = 25
	// Slice is a collection of items.
	Slice Type = 26
	// Enum is an enumeration.
	Enum Type = 27
	// Map is a map of values.
	Map Type = 28
	// Object is a generic object.
	Object Type = 29
	// Path is a normalized filesystem path.
	Path Type = 31
	// Status is a system error code.
	Status Type = 32
	// Flags is a bitmask.
	Flags Type = 34
	// Flags64 is a 64-bit bitmask.
	Flags64 Type = 35
	// Address is a memory address.
	Address Type = 36
)

// String returns the type name.
func (t Type) String() string {
	if name := platformTypeString(t); name != "" {
		return name
	}
	switch t {
	case Int8:
		return "int8"
	case Uint8:
		return "uint8"
	case Int16:
		return "int16"
	case Uint16:
		return "uint16"
	case Int32:
		return "int32"
	case Uint32:
		return "uint32"
	case Int64:
		return "int64"
	case Uint64:
		return "uint64"
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
