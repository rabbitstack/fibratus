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

import "strconv"

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
