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
	mapper := NewDevMapper()
	files := make([]string, 0, len(drives))
	for _, drive := range drives {
		files = append(files, fmt.Sprintf("%s:\\Windows\\system32\\kernel32.dll", drive))
	}
	var filename string
	for i := 0; i < len(drives); i++ {
		filename = mapper.Convert(fmt.Sprintf("\\Device\\HarddiskVolume%d\\Windows\\system32\\kernel32.dll", i))
		if !strings.HasPrefix(filename, "\\Device") {
			break
		}
	}
	assert.Contains(t, files, filename)
}
