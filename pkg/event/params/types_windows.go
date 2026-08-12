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
	// UnicodeString is a UTF-16LE string.
	UnicodeString Type = 1
	// AnsiString is an 8-bit character string.
	AnsiString Type = 2
	// GUID is a globally unique identifier.
	GUID Type = 15
	// Pointer is an architecture-sized pointer value.
	Pointer Type = 16
	// SID is a Windows security identifier.
	SID Type = 17
	// WbemSID is a Web-Based Enterprise Management security identifier.
	WbemSID Type = 20
	// DOSPath is a filesystem path in DOS device notation.
	DOSPath Type = 30
	// Key is a registry key.
	Key Type = 33
	// HandleType is a Windows handle type.
	HandleType Type = 37
)

func platformTypeString(t Type) string {
	switch t {
	case UnicodeString:
		return "unicode"
	case AnsiString:
		return "ansi"
	case SID, WbemSID:
		return "sid"
	default:
		return ""
	}
}
