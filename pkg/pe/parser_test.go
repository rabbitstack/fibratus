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
	"errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestParseFile(t *testing.T) {
	var tests = []struct {
		file             string
		hasSymbols       bool
		hasSections      bool
		hasImports       bool
		versionResources map[string]string
	}{
		{filepath.Join(os.Getenv("windir"), "notepad.exe"), true, true, true, map[string]string{"OriginalFilename": "NOTEPAD.EXE", "CompanyName": "Microsoft Corporation"}},
		{filepath.Join(os.Getenv("windir"), "regedit.exe"), true, true, true, nil},
		{filepath.Join(os.Getenv("windir"), "system32", "svchost.exe"), true, true, true, map[string]string{"OriginalFilename": "svchost.exe"}},
		{filepath.Join(os.Getenv("windir"), "system32", "kernel32.dll"), true, true, true, map[string]string{"InternalName": "kernel32"}},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			pe, err := ParseFile(tt.file,
				WithSections(),
				WithSymbols(),
				WithVersionResources(),
				WithSectionEntropy(),
				WithSectionMD5(),
			)
			if err != nil {
				t.Fatalf("%s: %v", tt.file, err)
			}
			if pe == nil {
				t.Fatalf("%s: PE metadata is nil", tt.file)
			}
			if len(pe.Symbols) > 0 != tt.hasSymbols {
				t.Errorf("%s: expected to have symbols", tt.file)
			}
			if len(pe.Sections) > 0 != tt.hasSections {
				t.Errorf("%s: expected to have sections", tt.file)
			}
			if len(pe.Imports) > 0 != tt.hasImports {
				t.Errorf("%s: expected to have imports", tt.file)
			}
			sec := pe.Sections[0]
			if sec.Md5 == "" {
				t.Errorf("%s: section should have MD5 hash", tt.file)
			}
			if sec.Entropy == 0.0 {
				t.Errorf("%s: section should have entropy value", tt.file)
			}
			if tt.versionResources != nil {
				for k, v := range tt.versionResources {
					val, ok := pe.VersionResources[k]
					if !ok {
						t.Errorf("%s: should have %s version resource", tt.file, k)
					}
					if val != v {
						t.Errorf("%s: expected: %s version resource got: %s", tt.file, v, val)
					}
				}
			}
		})
	}
}

func TestParseMem(t *testing.T) {
	var tests = []struct {
		executable       string
		expectedSections int
	}{
		{filepath.Join(os.Getenv("windir"), "notepad.exe"), 7},
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
		time.Sleep(time.Millisecond * 300)
		defer func() {
			_ = windows.TerminateProcess(pi.Process, 0)
		}()
		addr, err := getModuleBaseAddress(pi.ProcessId)
		if err != nil {
			t.Fatalf("%s: unable to get the base address: %v", tt.executable, err)
		}

		pe, err := ParseMem(pi.ProcessId, addr, false, WithSections())
		if err != nil {
			t.Fatalf("%s: %v", tt.executable, err)
		}
		if pe == nil {
			t.Fatalf("%s: PE metadata is nil", tt.executable)
		}
		if len(pe.Sections) != tt.expectedSections {
			t.Errorf("%s: expected: %d, got %d sections", tt.executable, tt.expectedSections, len(pe.Sections))
		}
	}
}

func getModuleBaseAddress(pid uint32) (uintptr, error) {
	var moduleHandles [1024]windows.Handle
	var cbNeeded uint32
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	if err := windows.EnumProcessModules(proc, &moduleHandles[0], 1024, &cbNeeded); err != nil {
		return 0, err
	}
	for _, moduleHandle := range moduleHandles[:uintptr(cbNeeded)/unsafe.Sizeof(moduleHandles[0])] {
		var moduleInfo windows.ModuleInfo
		if err := windows.GetModuleInformation(proc, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo))); err != nil {
			return 0, err
		}
		return moduleInfo.BaseOfDll, nil
	}
	return 0, errors.New("no modules found")
}
