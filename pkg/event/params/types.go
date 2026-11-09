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

const (
	// NA defines absent parameter's value
	NA = "na"
)

// Type defines an event parameter type.
type Type uint16

const (
	// Null is a null parameter type.
	Null Type = iota
	// Int8 is a signed 8-bit integer.
	Int8
	// Uint8 is an unsigned 8-bit integer.
	Uint8
	// Int16 is a signed 16-bit integer.
	Int16
	// Uint16 is an unsigned 16-bit integer.
	Uint16
	// Int32 is a signed 32-bit integer.
	Int32
	// Uint32 is an unsigned 32-bit integer.
	Uint32
	// Int64 is a signed 64-bit integer.
	Int64
	// Uint64 is an unsigned 64-bit integer.
	Uint64
	// Float is an IEEE 4-byte floating-point number.
	Float
	// Double is an IEEE 8-byte floating-point number.
	Double
	// String is a UTF-8 encoded string.
	String
	// Bool is a boolean value.
	Bool
	// Binary is variable-sized binary data.
	Binary
	// PID is a process identifier.
	PID
	// TID is a thread identifier.
	TID
	// Port is an endpoint port number.
	Port
	// IP is an IP address.
	IP
	// IPv4 is an IPv4 address.
	IPv4
	// IPv6 is an IPv6 address.
	IPv6
	// Time is a timestamp in nanoseconds.
	Time
	// Slice is a collection of items.
	Slice
	// Enumeration is a map of keys mapped to their values.
	Enum
	// Path is a normalized filesystem path.
	Path
	// Status is a system error code.
	Status
	// Flags32 is a 32-bit bitmask.
	Flags32
	// Flags64 is a 64-bit bitmask.
	Flags64
	// Address is a memory address.
	Address
	// Variant is a schema-only type for parameters whose logical type
	// is not known in advance, such as the registry data, which can be a
	// string, binary buffer or integer depending on the value type.
	// The parameter is rendered according to the kind of the stored value.
	Variant
	// Map represents a collection of key-value items.
	Map
	// maxType is the maximum shared type identifier
	maxType
)

// IsNumber determines if the type is one of the integer types.
func (t Type) IsNumber() bool {
	switch t {
	case Int8, Int16, Int32, Int64, Uint8, Uint16, Uint32, Uint64:
		return true
	default:
		return false
	}
}

// ParamOpts defines the options for the param constructor.
type ParamOpts struct {
	Flags Flags
	Enum  Enumeration
}

// ParamOption represents the option for the parameter literal constructor.
type ParamOption func(o *ParamOpts)

// WithFlags appends the parameter with a list of bitmask flags.
func WithFlags(flags Flags) ParamOption {
	return func(o *ParamOpts) {
		o.Flags = flags
	}
}

// WithEnum appends the parameter with the enum mapping.
func WithEnum(enum Enumeration) ParamOption {
	return func(o *ParamOpts) {
		o.Enum = enum
	}
}
