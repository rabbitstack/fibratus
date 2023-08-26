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

package pe

import (
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsHeaderModified(t *testing.T) {
	var tests = []struct {
		executable string
		modified   bool
	}{
		{filepath.Join(os.Getenv("windir"), "explorer.exe"), false},
	}

	for _, tt := range tests {
		var si windows.StartupInfo
		var pi windows.ProcessInformation
		argv := windows.StringToUTF16Ptr(tt.executable)
		err := windows.CreateProcess(
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
		require.NoError(t, err)
		for {
			if sys.IsProcessRunning(pi.Process) {
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
		defer func() {
			_ = windows.TerminateProcess(pi.Process, 0)
		}()
		addr, err := getModuleBaseAddress(pi.ProcessId)
		if err != nil {
			t.Fatalf("%s: unable to get the base address: %v", tt.executable, err)
		}
		file, err := ParseFile(tt.executable, WithSections())
		if err != nil {
			t.Fatalf("%s: %v", tt.executable, err)
		}
		mem, err := ParseMem(pi.ProcessId, addr, false, WithSections())
		if err != nil {
			t.Fatalf("%s: %v", tt.executable, err)
		}
		if mem == nil {
			t.Fatalf("%s: PE mem data is nil", tt.executable)
		}
		isHdrModified := file.IsHeaderModified(mem)
		if isHdrModified != tt.modified {
			t.Errorf("%s: expected %t, but got: %t", tt.executable, tt.modified, isHdrModified)
		}
	}
}
