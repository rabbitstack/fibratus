/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package sys

import (
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnumProcessModules(t *testing.T) {
	mods := EnumProcessModules(windows.GetCurrentProcessId())
	assert.True(t, len(mods) > 0)
	names := make([]string, 0, len(mods))
	for _, mod := range mods {
		names = append(names, filepath.Base(strings.ToLower(mod.Name)))
	}
	assert.Contains(t, names, "ntdll.dll")
}
