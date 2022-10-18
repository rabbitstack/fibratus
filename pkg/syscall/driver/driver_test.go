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

package driver

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnumDevices(t *testing.T) {
	drivers := EnumDevices()
	require.True(t, len(drivers) > 0)

	ntoskrnlFound := false
	for _, drv := range drivers {
		if strings.EqualFold(filepath.Base(drv.Filename), "ntoskrnl.exe") {
			ntoskrnlFound = true
			break
		}
	}
	assert.True(t, ntoskrnlFound)
}
