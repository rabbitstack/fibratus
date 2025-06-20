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

package sys

import (
	"golang.org/x/sys/windows"
)

const (
	// UntrustedRid designates the integrity level of anonymous
	// logged on processes. Write access is mostly blocked.
	UntrustedRid = 0x00000000

	// LowRid designates low process token integrity. Used for
	// AppContainers, browsers that access the Internet and
	// prevent most write access to objects on the system.
	LowRid = 0x00001000

	// MediumRid designates the token integrity default for most
	// processes. For authenticated users.
	MediumRid = 0x00002000

	// MediumPlusRid is often observed in AppContainer or UWP processes,
	// especially when they require elevated trust compared to a typical
	// Medium-level process but still shouldn't run with full administrative
	// privileges.
	MediumPlusRid = MediumRid | 0x100

	// HighRid is the integrity level for Administrator-level processes.
	// (Elevated) process with UAC.
	HighRid = 0x00003000

	// SystemRid is the integrity level reserved for system services/processes.
	SystemRid = 0x00004000

	// ProtectedProcessRid is not seen to be used by default. Windows Internals
	// book says it can be set by a kernel-mode caller.
	ProtectedProcessRid = 0x00005000
)

// RidToString given the SID representing the token mandatory label
// returns the string representation of the integrity level.
func RidToString(sid *windows.SID) string {
	if sid == nil {
		return "UNKNOWN"
	}
	switch sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)) {
	case UntrustedRid:
		return "UNTRUSTED"
	case LowRid:
		return "LOW"
	case MediumRid:
		return "MEDIUM"
	case MediumPlusRid:
		return "MEDIUM+"
	case HighRid:
		return "HIGH"
	case SystemRid:
		return "SYSTEM"
	case ProtectedProcessRid:
		return "PROTECTED"
	default:
		return "UNKNOWN"
	}
}
