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

import "golang.org/x/sys/windows"

// ProcessHandleTableEntryInfo is the structure that describes the process handle entry.
type ProcessHandleTableEntryInfo struct {
	Handle           windows.Handle
	HandleCount      uintptr
	PointerCount     uintptr
	GrantedAccess    uint32
	ObjectTypeIndex  uint32
	HandleAttributes uint32
	Reserved         uint32
}

// ProcessHandleSnapshotInformation is the structure that holds the process handle table.
type ProcessHandleSnapshotInformation struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]ProcessHandleTableEntryInfo
}

// SystemHandleTableEntryInfoEx is the structure that describes the process handle entry.
type SystemHandleTableEntryInfoEx struct {
	Object                uint64
	ProcessID             uintptr
	Handle                windows.Handle
	GrantedAccess         uint32
	CreatorBackTraceIndex uint8
	ObjectTypeIndex       uint8
	HandleAttributes      uint32
	Reserved              uint32
}

// SystemHandleInformationEx is the structures that holds the process handle table.
type SystemHandleInformationEx struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SystemHandleTableEntryInfoEx
}
