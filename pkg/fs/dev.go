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
	"os"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/sys"
)

const deviceOffset = 8
const vmsmbDevice = `\Device\vmsmb`

var (
	devMapper     *DevMapper
	onceDevMapper sync.Once
)

// GetDevMapper builds and returns the singleton dev mapper instance.
func GetDevMapper() *DevMapper {
	onceDevMapper.Do(func() {
		devMapper = newDevMapper()
	})
	return devMapper
}

// DevMapper converts the fully qualified file path and
// replaces the DOS device name with a drive letter.
type DevMapper struct {
	cache   map[string]string
	sysroot string
}

// newDevMapper creates a new instance of the DOS device replacer.
func newDevMapper() *DevMapper {
	m := &DevMapper{
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

func (m *DevMapper) Convert(path string) string {
	if path == "" || len(path) < deviceOffset {
		return path
	}

	// find the backslash index
	n := strings.Index(path[deviceOffset:], "\\")
	if n < 0 {
		if f, ok := m.cache[path]; ok {
			return f
		}
		return path
	}

	dev := path[:n+deviceOffset]
	if drive, ok := m.cache[dev]; ok {
		// the mapping for the DOS device exists
		return strings.Replace(path, dev, drive, 1)
	}

	switch {
	case dev == vmsmbDevice:
		// convert Windows Sandbox path to native path
		if n := strings.Index(path, "os"); n > 0 {
			return "C:" + path[n+2:]
		}
	case strings.HasPrefix(path, "\\SystemRoot"):
		// normalize paths starting with SystemRoot
		return strings.Replace(path, "\\SystemRoot", m.sysroot, 1)
	case strings.HasPrefix(path, "\\SYSTEMROOT"):
		// normalize paths starting with SYSTEMROOT
		return strings.Replace(path, "\\SYSTEMROOT", m.sysroot, 1)
	}

	return path
}
