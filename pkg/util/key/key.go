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
	"errors"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows/registry"
)

const (
	machineRoot    = `\REGISTRY\MACHINE`
	machineClasses = `\REGISTRY\MACHINE\SOFTWARE\CLASSES`
	comrootClasses = `\REGISTRY\COMROOT\CLASSES`
	userRoot       = `\REGISTRY\USER`
)

const classesSuffix = "_Classes"

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
	// Invalid represents an invalid registry key. For example, registry
	// hive used in Windows application isolation or sandboxing context
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

func hasPrefixFold(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}

// splitKey splits a native key name onto a root handle plus subkey.
func splitKey(path string) (Key, string) {
	if root, subkey, ok := matchPrefix(path, false); ok {
		return root, subkey
	}
	// Now match the slow path where registry keys can be reported with any casing
	if root, subkey, ok := matchPrefix(path, true); ok {
		return root, subkey
	}
	// Can return Invalid (e.g. \Registry\WC) for sandboxed hives
	return Invalid, path
}

// matchPrefix reports whether the registry path starts with the root prefix.
// If fold is set to true, registry keys can be reported with any casing.
func matchPrefix(path string, fold bool) (Key, string, bool) {
	hasPrefix := strings.HasPrefix
	if fold {
		hasPrefix = hasPrefixFold
	}
	switch {
	case hasPrefix(path, machineRoot):
		if hasPrefix(path, machineClasses) {
			return ClassesRoot, subkey(path, machineClasses), true
		}
		return LocalMachine, subkey(path, machineRoot), true
	case hasPrefix(path, userRoot):
		return Users, subkey(path, userRoot), true
	case hasPrefix(path, comrootClasses):
		return ClassesRoot, subkey(path, comrootClasses), true
	}
	return Invalid, path, false
}

var ErrInvalidRoot = errors.New("invalid root key")

// ReadValue reads the registry value from the specified key path.
// Returns the registry value type identifier, the value data and
// an error, if the value cannot be read.
func ReadValue(path string, value string) (uint32, any, error) {
	root, subkey := splitKey(strings.TrimSuffix(path, value))
	if root == Invalid {
		return 0, nil, ErrInvalidRoot
	}
	regKey, err := registry.OpenKey(registry.Key(root), subkey, registry.QUERY_VALUE)
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

// Format produces the full registry path (e.g. HKEY_LOCAL_MACHINE\SOFTWARE)
// from the native key name. If the native name has no known registry root
// the original native path is returned.
func Format(path string) string {
	root, subkey := splitKey(path)
	switch root {
	case Invalid:
		return path
	case Users:
		root, subkey = remapUserHive(subkey)
	}
	if subkey == "" {
		return root.String()
	}
	return root.String() + `\` + subkey
}

func isSID(s string) bool {
	return len(s) > 2 && (s[0] == 'S' || s[0] == 's') && s[1] == '-'
}

// remapUserHive receives the path without the root key prefix
// and attempts to remap it to the current user hive if the SID
// correspond to the currently logged-in user SID.
func remapUserHive(path string) (Key, string) {
	sid, subpath, _ := strings.Cut(path, `\`)
	if loggedSID == "" || !isSID(sid) {
		return Users, path
	}
	base := sid
	// Trim the _Classes suffix
	if n := len(sid); n >= len(classesSuffix) && sid[n-len(classesSuffix):] == classesSuffix {
		base = sid[:n-len(classesSuffix)]
	}
	if !strings.EqualFold(base, loggedSID) {
		return Users, path
	}
	// Handle per-user classes hive, where the SID contains
	// the `_Classes` suffix
	if len(base) != len(sid) {
		if subpath == "" {
			return CurrentUser, `Software\Classes`
		}
		return CurrentUser, `Software\Classes\` + subpath
	}
	// SID doesn't contain the `_Classes` suffix, but _Classes
	// is its adjacent path component
	if subpath == classesSuffix {
		return CurrentUser, `Software\Classes`
	}
	if len(subpath) >= len(classesSuffix) && strings.HasPrefix(subpath, classesSuffix) {
		return CurrentUser, `Software\Classes` + subpath[len(classesSuffix):]
	}
	return CurrentUser, subpath
}

func subkey(key string, prefix string) string {
	if len(key) > len(prefix) {
		return key[len(prefix)+1:]
	}
	return ""
}
