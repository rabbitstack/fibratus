/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package stringcache

import (
	"hash/maphash"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cacheSize = 8192 // power of two

type slot struct {
	key string // owned copy of the raw UTF-16 bytes
	val string // decoded UTF-8
}

// StringCache is NOT goroutine-safe
type StringCache struct {
	seed  maphash.Seed
	slots [cacheSize]slot
}

func New() *StringCache { return &StringCache{seed: maphash.MakeSeed()} }

func (c *StringCache) slotFor(view string) *slot {
	return &c.slots[maphash.String(c.seed, view)&(cacheSize-1)]
}

// Lookup returns the value cached for the raw UTF-16 key, if present.
// It never decodes and never allocates.
func (c *StringCache) Lookup(k []uint16) (string, bool) {
	if k == nil {
		return "", false
	}
	k = trimNul(k)
	if len(k) == 0 {
		return "", false
	}
	view := utf16View(k)
	if s := c.slotFor(view); s.key == view {
		return s.val, true
	}
	return "", false
}

// Add maps the raw UTF-16 key to val. val is stored as is, so it can be any
// string derived from the key (a normalized path, a resolved name, ...).
// It must not alias the ETW buffer; the key bytes are cloned internally.
func (c *StringCache) Add(k []uint16, val string) {
	if k == nil {
		return
	}
	k = trimNul(k)
	if len(k) == 0 {
		return
	}
	view := utf16View(k)
	s := c.slotFor(view)
	if s.key == view {
		s.val = val // same key: just replace the value, keep the key copy
		return
	}
	s.key = strings.Clone(view) // evicts whatever was in the slot
	s.val = val
}

// Get decodes the key with the default UTF-16 to UTF-8 conversion on a miss.
func (c *StringCache) Get(k []uint16) string {
	if k == nil {
		return ""
	}
	if v, ok := c.Lookup(k); ok {
		return v
	}
	v := windows.UTF16ToString(trimNul(k))
	c.Add(k, v)
	return v
}

func utf16View(k []uint16) string {
	return unsafe.String((*byte)(unsafe.Pointer(unsafe.SliceData(k))), len(k)*2)
}

func trimNul(k []uint16) []uint16 {
	n := len(k)
	for n > 0 && k[n-1] == 0 {
		n--
	}
	return k[:n]
}
