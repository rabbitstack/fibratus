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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetFileType(t *testing.T) {
	var tests = []struct {
		filename string
		opts     uint32
		wants    FileType
	}{
		{
			`_fixtures`,
			16777249,
			Directory,
		},
		{
			`_fixtures`,
			25165857,
			Directory,
		},
		{
			`C:\Users\bunny\AppData\Local\Mozilla\Firefox\Profiles\profile1.tmp`,
			18874368,
			Regular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			filename, opts := tt.filename, tt.opts
			wants := tt.wants
			assert.Equal(t, wants, GetFileType(filename, opts))
		})
	}
}
