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
	// GUID is a globally unique identifier.
	GUID Type = iota + maxType + 1
	// SID is a Windows security identifier.
	SID
	// WbemSID is a Web-Based Enterprise Management security identifier.
	WbemSID
	// DOSPath is a filesystem path in DOS device notation.
	DOSPath
	// Key is a registry key.
	Key
	// HandleType is a Windows handle type.
	HandleType
	// TokeIntegrityLevel is the process token integrity mandatory label SID.
	TokenIntegrityLevel
)

// String returns the type name.
func (t Type) String() string {
	switch t {
	case String:
		return "string"
	case SID, WbemSID:
		return "sid"
	case Int8:
		return "int8"
	case Uint8:
		return "uint8"
	case Int16:
		return "int16"
	case Uint16:
		return "uint16"
	case Int32:
		return "int32"
	case Uint32:
		return "uint32"
	case Int64:
		return "int64"
	case Uint64:
		return "uint64"
	case TID:
		return "tid"
	case PID:
		return "pid"
	case Port:
		return "port"
	case IPv6:
		return "ipv6"
	case IPv4:
		return "ipv4"
	default:
		return "unknown"
	}
}
