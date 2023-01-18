//go:build yara
// +build yara

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

package functions

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

var pi syscall.ProcessInformation

func TestYara(t *testing.T) {
	var tests = []struct {
		args     []interface{}
		expected bool
		rules    string
	}{
		{
			[]interface{}{uint32(runNotepad())},
			true,
			`
rule Notepad : notepad
{
	meta:
		severity = "Normal"
		date = "2016-07"
	strings:
		$c0 = "Notepad" fullword ascii
	condition:
		$c0
}
			`,
		},
		{
			[]interface{}{"_fixtures/yara-test.dll"},
			true,
			`
rule DLL : dll
{
	meta:
		severity = "Critical"
		date = "2020-07"
	strings:
		$c0 = "Go" fullword ascii
	condition:
		$c0
}
			`,
		},
		{
			[]interface{}{readNotepadBytes()},
			true,
			`
rule Notepad : notepad
{
	meta:
		severity = "Normal"
		date = "2016-07"
	strings:
		$c0 = "Notepad" fullword ascii
	condition:
		$c0
}
			`,
		},
	}

	for i, tt := range tests {
		f := Yara{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
	defer syscall.TerminateProcess(pi.Process, uint32(257))
}

func runNotepad() uint32 {
	var si syscall.StartupInfo
	argv := syscall.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "notepad.exe"))
	err := syscall.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		return 0
	}
	return pi.ProcessId
}

func readNotepadBytes() []byte {
	p := filepath.Join(os.Getenv("windir"), "notepad.exe")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}
