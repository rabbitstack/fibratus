/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShouldSkipProcess(t *testing.T) {
	var tests = []struct {
		c    Config
		proc string
		skip bool
	}{
		{
			Config{ExcludedProcesses: []string{"C:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\svchost.exe"}},
			"C:\\WINDOWS\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\*.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\*.exe"}},
			"C:\\Windows\\hh.exe",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.proc, func(t *testing.T) {
			assert.Equal(t, tt.skip, tt.c.ShouldSkipProcess(tt.proc))
		})
	}
}

func TestShouldSkipFile(t *testing.T) {
	var tests = []struct {
		c    Config
		file string
		skip bool
	}{
		{
			Config{ExcludedFiles: []string{"C:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\System32\\svchost.exe", "?:\\Program Files\\*\\*.exe"}},
			"C:\\Program Files\\dotnet\\dotnet.exe",
			true,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\*\\svchost.exe"}},
			"C:\\Program Files\\dotnet\\dotnet.exe",
			false,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\*\\*.exe", "C:\\Program Files\\Logs\\*\\*.dll"}},
			"C:\\Program Files\\dotnet\\sdk\\8.0.300\\Microsoft.build.dll",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			assert.Equal(t, tt.skip, tt.c.ShouldSkipFile(tt.file))
		})
	}
}

func TestAlertTemplate(t *testing.T) {

}
