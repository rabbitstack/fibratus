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

package ktypes

import "math"

// Ktype represents the kernel event type which usually maps to syscall identifier
type Ktype uint16

const (
	// Read reads data from a file descriptor
	Read Ktype = iota
)

// UnknownKtype assumes we'll never exhaust the 1<<16 - 1 syscall range
const UnknownKtype Ktype = math.MaxUint16

// String returns human-readable event representation.
func (k Ktype) String() string {
	switch k {
	case Read:
		return "read"
	default:
		return "unknown"
	}
}

// RawID coerces the ktype to uint32 value to satisfy
// eBPF map marshaller alignment requirements.
func (k Ktype) RawID() uint32 { return uint32(k) }

func (k Ktype) Hash() uint32 { return 0 }
