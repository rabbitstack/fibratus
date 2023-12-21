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

package fs

import (
	"github.com/rabbitstack/fibratus/pkg/sys"
	"strings"
)

const deviceOffset = 8

// DevMapper is the minimal interface for the device converters.
type DevMapper interface {
	// Convert receives the fully qualified file path and replaces the DOS device name with a drive letter.
	Convert(filename string) string
}

type mapper struct {
	cache map[string]string
}

// NewDevMapper creates a new instance of the DOS device replacer.
func NewDevMapper() DevMapper {
	m := &mapper{
		cache: make(map[string]string),
	}
	// loop through logical drives and query the DOS device name
	for _, drive := range sys.GetLogicalDrives() {
		device, err := sys.QueryDosDevice(drive)
		if err != nil {
			continue
		}
		m.cache[device] = drive
	}
	return m
}

func (m *mapper) Convert(filename string) string {
	if filename == "" || len(filename) < deviceOffset {
		return filename
	}
	i := strings.Index(filename[deviceOffset:], "\\")
	if i < 0 {
		if f, ok := m.cache[filename]; ok {
			return f
		}
		return filename
	}
	dev := filename[:i+deviceOffset]
	if drive, ok := m.cache[dev]; ok {
		return strings.Replace(filename, dev, drive, 1)
	}
	return filename
}
