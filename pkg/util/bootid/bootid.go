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

package bootid

import "unsafe"

// The KUSER_SHARED_DATA structure defines a data region that the kernel places
// at a static address for access within user-mode. It is important to note that
// this region of memory, when accessed via user-mode, is read only. The read-only
// user-mode address for the shared data is 0x7FFE0000.
const kuserSharedData uintptr = 0x7FFE0000

const offset uintptr = 0x02C4 // BootId field offset

// Read obtains the value of the BootId field in the KUSER_SHARED_DATA structure.
func Read() uint64 {
	return uint64(*(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(kuserSharedData)) + offset)))
}
