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
	"expvar"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/syscall/security"
)

var (
	hklmPrefixes = []string{"\\REGISTRY\\MACHINE", "\\Registry\\Machine", "\\Registry\\MACHINE"}
	hkcrPrefixes = []string{"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", "\\Registry\\Machine\\Software\\Classes"}
	hkuPrefixes  = []string{"\\REGISTRY\\USER", "\\Registry\\User"}
)

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

var (
	keys = make([]string, 0)
	mux  sync.Mutex
	once sync.Once
	// sidsCount reflects the total count of the resolved SIDs
	sidsCount  = expvar.NewInt("sids.count")
	lookupSids = security.LookupAllSids
)

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

// ReadValue reads the registry value from the specified key path.
func (key Key) ReadValue(k string) (uint32, any, error) {
	// sometimes the value can contain slashes, in which
	// case we use it as a separator between subkey
	n := strings.Index(k, "\\\\")
	var subkey string
	var value string
	if n > 0 {
		subkey, value = k[0:n], k[n+1:]
	} else {
		subkey, value = filepath.Split(k)
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

	once.Do(func() { initKeys() })

	if root, k := findSIDKey(key); root != Invalid {
		return root, k
	}
	for _, p := range hkuPrefixes {
		if strings.HasPrefix(key, p) {
			return Users, subkey(key, p)
		}
	}
	return Invalid, key
}

// initKeys retrieves all security identifiers on the local machine and builds a slice of
// prefixes targeting \\Registry\\User\\<sid> and \\Registry\\User\\<sid>\\_Classes keys.
func initKeys() {
	sids, err := lookupSids()
	if err != nil {
		return
	}
	sidsCount.Add(int64(len(sids)))
	mux.Lock()
	defer mux.Unlock()
	for _, sid := range sids {
		user := "\\REGISTRY\\USER\\" + sid
		keys = append(keys, user, user+"\\_Classes")
	}
}

func findSIDKey(key string) (Key, string) {
	mux.Lock()
	defer mux.Unlock()
	for _, k := range keys {
		if strings.HasPrefix(key, k) {
			if strings.Contains(key, "_Classes") {
				return CurrentUser, strings.Replace(subkey(key, k), "_Classes", "Software\\Classes", -1)
			}
			return CurrentUser, subkey(key, k)
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
