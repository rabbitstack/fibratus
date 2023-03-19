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
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile(t *testing.T) {
	var tests = []struct {
		file        string
		hasSymbols  bool
		hasSections bool
		hasImports  bool
	}{
		{filepath.Join(os.Getenv("windir"), "notepad.exe"), true, true, true},
		{filepath.Join(os.Getenv("windir"), "regedit.exe"), true, true, true},
		{filepath.Join(os.Getenv("windir"), "system32", "svchost.exe"), true, true, true},
		{filepath.Join(os.Getenv("windir"), "system32", "kernel32.dll"), true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			pe, err := ParseFile(tt.file, WithSections(), WithSymbols(), WithVersionResources())
			if err != nil {
				t.Errorf("%s: %v", tt.file, err)
			}
			if pe == nil {
				t.Errorf("%s: PE metadata is nil", tt.file)
			}
			fmt.Println(pe.String())
		})
	}
}
