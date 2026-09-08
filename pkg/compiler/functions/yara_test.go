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
	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() {
	scanTimeout = time.Minute
}

func TestYara(t *testing.T) {
	pid, proc := runNotepad()
	for {
		if sys.IsProcessRunning(proc) {
			break
		}
		time.Sleep(time.Millisecond * 100)
		log.Infof("%d pid not yet ready", pid)
	}
	defer windows.TerminateProcess(proc, 0)

	var tests = []struct {
		args     []interface{}
		expected bool
	}{
		{
			[]interface{}{pid, `
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
					`},
			true,
		},
		{
			[]interface{}{"_fixtures/yara-test.dll", `
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
					`},
			true,
		},
		{
			[]interface{}{readNotepadBytes(), `
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
			`},
			true,
		},
		{
			[]interface{}{pid, `
		rule Notepad : notepad
		{
			meta:
				severity = "Normal"
				date = "2016-07"
			strings:
				$c0 = "Notfound" fullword ascii
			condition:
				$c0
		}
					`},
			false,
		},
	}

	for i, tt := range tests {
		f := Yara{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
}

func runNotepad() (uint32, windows.Handle) {
	var si windows.StartupInfo
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	var pi windows.ProcessInformation
	argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "notepad.exe"))
	err := windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&si,
		&pi)
	if err != nil {
		return 0, 0
	}
	return pi.ProcessId, pi.Process
}

func readNotepadBytes() []byte {
	p := filepath.Join(os.Getenv("windir"), "notepad.exe")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}
