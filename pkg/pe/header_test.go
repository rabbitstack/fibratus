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
	"fmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsHeaderModified(t *testing.T) {
	var tests = []struct {
		executable string
		modified   bool
	}{
		{filepath.Join(os.Getenv("windir"), "explorer.exe"), false},
		{filepath.Join(os.Getenv("windir"), "system32", "calc.exe"), true},
	}

	// perform PE injection on the calc.exe executable with
	// process overwriting technique as explained in the repo
	// https://github.com/hasherezade/process_overwriting
	cmd := exec.Command("_fixtures/process_overwriting.exe", "_fixtures/shellcode.bin")
	require.NoError(t, cmd.Run())

	for _, tt := range tests {
		pid, err := findProcessID(tt.executable)
		require.NoError(t, err)
		addr, err := getModuleBaseAddress(pid)
		if err != nil {
			t.Fatalf("%s: unable to get the base address: %v", tt.executable, err)
		}
		file, err := ParseFile(tt.executable, WithSections())
		if err != nil {
			t.Fatalf("%s: %v", tt.executable, err)
		}
		mem, err := ParseMem(pid, addr, false, WithSections())
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
		// terminate injected process
		if filepath.Base(tt.executable) == "calc.exe" {
			proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
			if err != nil {
				continue
			}
			windows.TerminateProcess(proc, 1)
		}
	}
}

func findProcessID(image string) (uint32, error) {
	const processEntrySize = 568
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.Close(snap)
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		err := windows.Process32Next(snap, &p)
		if err != nil {
			break
		}
		s := windows.UTF16ToString(p.ExeFile[:])
		if strings.EqualFold(s, filepath.Base(image)) {
			return p.ProcessID, nil
		}
	}
	return 0, fmt.Errorf("no process for %s image", image)
}
