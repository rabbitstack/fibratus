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

import (
	"strconv"
	"sync"
)

// Address represents the memory address
type Address uint64

// Callstack is the type alias for callstack return addresses
type Callstack []Address

const callstackDepthHint = 60

var callstackPool = sync.Pool{
	New: func() any {
		c := make(Callstack, 0, callstackDepthHint)
		return &c
	},
}

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

func GetCallstack() Callstack {
	return (*callstackPool.Get().(*Callstack))[:0]
}

func (c Callstack) ReleasePool() {
	if cap(c) > callstackDepthHint*4 {
		return // drop outlier-sized buffers rather than pooling them permanently
	}
	c = c[:0]
	callstackPool.Put(&c)
}
