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
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var drives = []string{
	"A",
	"B",
	"C",
	"D",
	"E",
	"F",
	"G",
	"H",
	"I",
	"J",
	"K",
	"L",
	"M",
	"N",
	"O",
	"P",
	"Q",
	"R",
	"S",
	"T",
	"U",
	"V",
	"W",
	"X",
	"Y",
	"Z"}

func TestConvertDosDevice(t *testing.T) {
	m := NewDevMapper()
	files := make([]string, 0, len(drives))

	for _, drive := range drives {
		files = append(files, fmt.Sprintf("%s:\\Windows\\system32\\kernel32.dll", drive))
	}

	var filename string
	for i := 0; i < len(drives); i++ {
		filename = m.Convert(fmt.Sprintf("\\Device\\HarddiskVolume%d\\Windows\\system32\\kernel32.dll", i))
		if !strings.HasPrefix(filename, "\\Device") {
			break
		}
	}
	assert.Contains(t, files, filename)

	m.(*mapper).cache["\\Device\\HarddiskVolume1"] = "C:"
	m.(*mapper).sysroot = "C:\\Windows"

	var tests = []struct {
		inputFilename    string
		expectedFilename string
	}{
		{"\\Device\\HarddiskVolume1\\Windows\\system32\\kernel32.dll", "C:\\Windows\\system32\\kernel32.dll"},
		{"\\Device\\HarddiskVolume5\\Windows\\system32\\kernel32.dll", "\\Device\\HarddiskVolume5\\Windows\\system32\\kernel32.dll"},
		{"\\Device\\vmsmb\\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\\os\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\ntdll.dll"},
		{"\\SystemRoot\\system32\\drivers\\wd\\WdNisDrv.sys", "C:\\Windows\\system32\\drivers\\wd\\WdNisDrv.sys"},
		{"\\SYSTEMROOT\\system32\\drivers\\wd\\WdNisDrv.sys", "C:\\Windows\\system32\\drivers\\wd\\WdNisDrv.sys"},
		{"\\Device\\Mup", "\\Device\\Mup"},
	}

	for _, tt := range tests {
		t.Run(tt.inputFilename, func(t *testing.T) {
			assert.Equal(t, tt.expectedFilename, m.Convert(tt.inputFilename))
		})
	}
}
