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

package sys

// MemoryWorkingSetExInformation describes the attributes of the memory region.
type MemoryWorkingSetExInformation struct {
	VirtualAddress    uintptr
	VirtualAttributes MemoryWorkingSetExBlock
}

type MemoryWorkingSetExBlock uintptr

// Valid if this bit is 1, the subsequent members are valid. Otherwise, they should be ignored.
func (b MemoryWorkingSetExBlock) Valid() bool {
	return b&1 != 0
}

// ShareCount specifies the number of processes that share this page. The maximum value of this member is 7.
func (b MemoryWorkingSetExBlock) ShareCount() uintptr {
	return (uintptr(b) >> 1) & ((1 << 3) - 1)
}

// Win32Protection specifies the memory protection attributes of the page.
func (b MemoryWorkingSetExBlock) Win32Protection() uintptr {
	return (uintptr(b) >> 4) & ((1 << 11) - 1)
}

// Shared evaluates to true if the page can be shared or false otherwise.
func (b MemoryWorkingSetExBlock) Shared() bool {
	return b&(1<<15) != 0
}

// Node represents the NUMA node. The maximum value of this member is 63.
func (b MemoryWorkingSetExBlock) Node() uintptr {
	return (uintptr(b) >> 16) & ((1 << 6) - 1)
}

// Locked returns true if the virtual page is locked in physical memory.
func (b MemoryWorkingSetExBlock) Locked() bool {
	return b&(1<<15) != 0
}

// LargePage returns true if the page is a large page.
func (b MemoryWorkingSetExBlock) LargePage() bool {
	return b&(1<<16) != 0
}

// SharedOriginal evaluates to true if the page can be shared or false otherwise.
func (b MemoryWorkingSetExBlock) SharedOriginal() bool {
	return b&(1<<30) != 0
}

// Bad indicates the page has been reported as bad.
func (b MemoryWorkingSetExBlock) Bad() bool {
	return b&(1<<31) != 0
}
