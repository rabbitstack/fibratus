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

package registry

// Key is the type alias for the registry root keys
type Key uint32

const (
	InvalidKey Key = 0
)

const (
	ClassesRoot Key = 0x80000000 + iota
	CurrentUser
	LocalMachine
	Users
	Hive
)

// String returns a human-readable root key name.
func (k Key) String() string {
	switch k {
	case ClassesRoot:
		return "HKEY_CLASSES_ROOT"
	case CurrentUser:
		return "HKEY_CURRENT_USER"
	case LocalMachine:
		return "HKEY_LOCAL_MACHINE"
	case Users:
		return "HKEY_USERS"
	case Hive:
		return ""
	default:
		return "Unknown"
	}
}
