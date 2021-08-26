// +build windows

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

// SizeOf returns the size in bytes of the event parameters
// that are known at compile time. This can notably offload
// the API calls that fetch the property size at runtime.
func SizeOf(kpar string) uint32 {
	switch kpar {
	case RegKeyHandle, KstackLimit, KstackBase, UstackLimit,
		UstackBase, ThreadEntrypoint, ImageBase, ImageSize,
		ImageDefaultBase, DTB, ProcessObject, FileIrpPtr, FileObject,
		FileExtraInfo, HandleObject, FileKey, FileOffset:
		return 8
	case NTStatus, ProcessID, ThreadID, ProcessParentID,
		SessionID, ExitStatus, FileCreateOptions, FileShareMask,
		HandleID, FileIoSize, FileInfoClass:
		return 4
	case NetDport, NetSport, HandleObjectTypeID:
		return 2
	case PagePrio, BasePrio, IOPrio:
		return 1
	default:
		return 0
	}
}
