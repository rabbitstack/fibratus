//go:build windows
// +build windows

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

package key

import (
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	hklmPrefixes = []string{"\\REGISTRY\\MACHINE", "\\Registry\\Machine", "\\Registry\\MACHINE", "\\registry\\machine"}
	hkcrPrefixes = []string{"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", "\\Registry\\Machine\\Software\\Classes", "\\REGISTRY\\COMROOT\\CLASSES"}
	hkuPrefixes  = []string{"\\REGISTRY\\USER", "\\Registry\\User"}
)

// rx detects a file path starting with a drive letter, e.g. C:\
var rx = regexp.MustCompile(`[A-Za-z]:\\`)

var loggedSID = getLoggedSID()

func getLoggedSID() string {
	wts, err := sys.LookupActiveWTS()
	if err != nil {
		return ""
	}
	sid, err := wts.SID()
	if err != nil {
		return ""
	}
	return sid.String()
}

// Key is the type alias for the registry key
type Key registry.Key

var (
	Users        = Key(registry.USERS)
	CurrentUser  = Key(registry.CURRENT_USER)
	LocalMachine = Key(registry.LOCAL_MACHINE)
	ClassesRoot  = Key(registry.CLASSES_ROOT)
	// Invalid represents an invalid registry key
	Invalid = Key(registry.Key(0))
)

// RegistryValueTypes enumerate all possible registry value types.
var RegistryValueTypes = map[uint32]string{
	registry.DWORD:     "REG_DWORD",
	registry.QWORD:     "REG_QWORD",
	registry.SZ:        "REG_SZ",
	registry.EXPAND_SZ: "REG_EXPAND_SZ",
	registry.MULTI_SZ:  "REG_MULTI_SZ",
	registry.BINARY:    "REG_BINARY",
}

// String converts registry root key identifier to string.
func (key Key) String() string {
	switch key {
	case Users:
		return "HKEY_USERS"
	case ClassesRoot:
		return "HKEY_CLASSES_ROOT"
	case LocalMachine:
		return "HKEY_LOCAL_MACHINE"
	case CurrentUser:
		return "HKEY_CURRENT_USER"
	default:
		return "Unknown"
	}
}

func shiftPath(k, s, v string) (string, string) {
	r := rx.FindString(s)
	if r == "" {
		return s, v
	}
	n := strings.LastIndex(s, r)
	for n > 0 {
		n--
		// find first slash occurrence backwards
		if s[n] == '\\' {
			return k[:n], k[n+1:]
		}
	}
	return s, v
}

// cleanSID returns the SID without trailing identifiers.
// In some circumstances, the SID can contain the `_Classes`
// suffix.
func cleanSID(sid string) string {
	return strings.TrimSuffix(sid, "_Classes")
}

// ReadValue reads the registry value from the specified key path.
func (key Key) ReadValue(k string) (uint32, any, error) {
	// sometimes the value can contain slashes, in which
	// case we use it as a separator between subkey. For
	// example, \Device\HarddiskVolume4\Windows\regedit.exe
	n := strings.Index(k, "\\\\")
	var subkey string
	var value string
	if n > 0 {
		subkey, value = k[0:n], k[n+1:]
	} else {
		subkey, value = filepath.Split(k)
		// here we handle another corner case
		// when the value can contain a file
		// path starting with a drive letter
		subkey, value = shiftPath(k, subkey, value)
	}
	regKey, err := registry.OpenKey(registry.Key(key), subkey, registry.QUERY_VALUE)
	if err != nil {
		return 0, nil, err
	}
	defer regKey.Close()

	b := make([]byte, 0)
	_, typ, err := regKey.GetValue(value, b)
	if err != nil {
		return 0, nil, err
	}
	var val any
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err = regKey.GetStringValue(value)
	case registry.DWORD, registry.QWORD:
		val, _, err = regKey.GetIntegerValue(value)
	case registry.MULTI_SZ:
		val, _, err = regKey.GetStringsValue(value)
	case registry.BINARY:
		val, _, err = regKey.GetBinaryValue(value)
	}
	if err != nil {
		return 0, nil, err
	}
	return typ, val, nil
}

// Format produces a root,key tuple from registry native key name.
func Format(key string) (Key, string) {
	for _, p := range hklmPrefixes {
		if strings.HasPrefix(key, p) {
			return LocalMachine, subkey(key, p)
		}
	}
	for _, p := range hkcrPrefixes {
		if strings.HasPrefix(key, p) {
			return ClassesRoot, subkey(key, p)
		}
	}
	for _, p := range hkuPrefixes {
		if strings.HasPrefix(key, p) {
			path := subkey(key, p)
			n := strings.Index(path, "\\")
			var sid string
			if n > 0 && path[0] == 'S' {
				sid = path[:n]
			} else if len(path) > 0 && path[0] == 'S' {
				sid = path
			}
			// if the HKEY_USERS hive sid is equal to
			// the sid of the currently logged user, we
			// remap the root key to HKEY_CURRENT_USER
			switch {
			case cleanSID(sid) == loggedSID && strings.Contains(path, "_Classes"):
				if strings.HasSuffix(sid, "_Classes") {
					return CurrentUser, "Software\\Classes\\" + path[n+1:]
				}
				return CurrentUser, strings.Replace(path[n+1:], "_Classes", "Software\\Classes", 1)
			case sid == loggedSID:
				if len(path) == len(loggedSID) {
					return CurrentUser, ""
				}
				return CurrentUser, path[n+1:]
			default:
				return Users, path
			}
		}
	}
	return Invalid, key
}

func subkey(key string, prefix string) string {
	if len(key) > len(prefix) {
		return key[len(prefix)+1:]
	}
	return ""
}
