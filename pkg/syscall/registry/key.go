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
	// InvalidKey designates invalid registry key.
	InvalidKey Key = 0
)

const (
	// ClassesRoot represents the HKEY_CLASSES_ROOT hive
	ClassesRoot Key = 0x80000000 + iota
	// CurrentUser represents the HKEY_CURRENT_USER hive
	CurrentUser
	// LocalMachine represents the HKEY_LOCAL_MACHINE hive
	LocalMachine
	// Users represents the HKEY_USERS hive
	Users
	// Hive represents the global hive that doesn't fall into category of any of the previous keys.
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
