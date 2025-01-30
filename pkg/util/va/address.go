/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package va

import "strconv"

// Address represents the memory address
type Address uint64

// Hex returns the hexadecimal representation of the memory address.
func (a Address) String() string   { return strconv.FormatUint(uint64(a), 16) }
func (a Address) Uint64() uint64   { return uint64(a) }
func (a Address) Uintptr() uintptr { return uintptr(a) }
func (a Address) IsZero() bool     { return a == 0 }

// Inc increments the address by given offset.
func (a Address) Inc(offset uint64) Address {
	a += Address(offset)
	return a
}

// Dec decrements the address by given offset.
func (a Address) Dec(offset uint64) Address {
	a -= Address(offset)
	return a
}

// InSystemRange determines if this address is in the system address space range.
// The kernel preferentially uses these two ranges to load DLLs at shared addresses.
func (a Address) InSystemRange() bool { return a >= 0xfffff80000000000 && a < 0xffffffffffffffff }
