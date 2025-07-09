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
	"os"
	"strings"
)

const deviceOffset = 8
const vmsmbDevice = `\Device\vmsmb`

// DevMapper is the minimal interface for the device converters.
type DevMapper interface {
	// Convert receives the fully qualified file path and replaces the DOS device name with a drive letter.
	Convert(filename string) string
}

type mapper struct {
	cache   map[string]string
	sysroot string
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

	// resolve the SystemRoot environment variable
	m.sysroot = os.Getenv("SystemRoot")
	if m.sysroot == "" {
		m.sysroot = os.Getenv("SYSTEMROOT")
	}

	return m
}

func (m *mapper) Convert(filename string) string {
	if filename == "" || len(filename) < deviceOffset {
		return filename
	}

	// find the backslash index
	n := strings.Index(filename[deviceOffset:], "\\")
	if n < 0 {
		if f, ok := m.cache[filename]; ok {
			return f
		}
		return filename
	}

	dev := filename[:n+deviceOffset]
	if drive, ok := m.cache[dev]; ok {
		// the mapping for the DOS device exists
		return strings.Replace(filename, dev, drive, 1)
	}

	switch {
	case dev == vmsmbDevice:
		// convert Windows Sandbox path to native path
		if n := strings.Index(filename, "os"); n > 0 {
			return "C:" + filename[n+2:]
		}
	case strings.HasPrefix(filename, "\\SystemRoot"):
		// normalize paths starting with SystemRoot
		return strings.Replace(filename, "\\SystemRoot", m.sysroot, 1)
	case strings.HasPrefix(filename, "\\SYSTEMROOT"):
		// normalize paths starting with SYSTEMROOT
		return strings.Replace(filename, "\\SYSTEMROOT", m.sysroot, 1)
	}

	return filename
}
