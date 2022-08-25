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

package handle

import (
	"expvar"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/syscall/registry"
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
)

const (
	hklmPrefixUppercase   = "\\REGISTRY\\MACHINE"
	hklmPrefixCapitalized = "\\Registry\\Machine"
	hkcrPrefixUppercase   = "\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES"
	hkcrPrefixCapitalized = "\\Registry\\Machine\\Software\\Classes"
	hkuPrefixUppercase    = "\\REGISTRY\\USER"
	hkuPrefixCapitalized  = "\\Registry\\User"
	// hive represents an application hive. Application hives are loaded by user-mode processes via RegLoadAppKey to store application-specific state data.
	hive = "\\REGISTRY\\A"
)

var (
	keys = make([]string, 0)
	mux  sync.Mutex
	once sync.Once
	// sidsCount reflects the total count of the resolved SIDs
	sidsCount  = expvar.NewInt("sids.count")
	lookupSids = security.LookupAllSids
)

// FormatKey produces a root,key tuple from registry native key name.
func FormatKey(key string) (registry.Key, string) {
	if strings.HasPrefix(key, hklmPrefixUppercase) || strings.HasPrefix(key, hklmPrefixCapitalized) {
		return registry.LocalMachine, subkey(key, hklmPrefixUppercase)
	}

	if strings.HasPrefix(key, hkcrPrefixUppercase) || strings.HasPrefix(key, hkcrPrefixCapitalized) {
		return registry.ClassesRoot, subkey(key, hkcrPrefixUppercase)
	}

	once.Do(func() { initKeys() })

	if root, k := findSIDKey(key); root != registry.InvalidKey {
		return root, k
	}

	if strings.HasPrefix(key, hkuPrefixUppercase) || strings.HasPrefix(key, hkuPrefixCapitalized) {
		return registry.Users, subkey(key, hkuPrefixUppercase)
	}

	if strings.HasPrefix(key, hive) {
		return registry.Hive, key
	}

	return registry.InvalidKey, key
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
		user := hkuPrefixUppercase + "\\" + sid
		keys = append(keys, user, user+"\\_Classes")
	}
}

func findSIDKey(key string) (registry.Key, string) {
	mux.Lock()
	defer mux.Unlock()
	for _, k := range keys {
		if strings.HasPrefix(key, k) {
			if strings.Contains(key, "_Classes") {
				return registry.CurrentUser, strings.Replace(subkey(key, k), "_Classes", "Software\\Classes", -1)
			}
			return registry.CurrentUser, subkey(key, k)
		}
	}
	return registry.InvalidKey, key
}

func subkey(key string, prefix string) string {
	if len(key) > len(prefix) {
		return key[len(prefix)+1:]
	}
	return ""
}
