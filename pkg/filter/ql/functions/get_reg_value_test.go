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
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
	"testing"
)

func TestGetRegValue(t *testing.T) {
	var tests = []struct {
		args     []interface{}
		expected interface{}
	}{
		{
			[]interface{}{"HKCU\\Volatile Environment\\FibratusTestDword"},
			uint32(1),
		},
		{
			[]interface{}{"HKEY_CURRENT_USER\\Volatile Environment\\FibratusTestQword"},
			uint64(1000),
		},
		{
			[]interface{}{"HKCU\\Volatile Environment\\FibratusTestSz"},
			"fibratus",
		},
		{
			[]interface{}{"HKCU\\Volatile Environment\\FibratusTestMultiSz"},
			[]string{"fibratus", "tracing"},
		},
		{
			[]interface{}{"HKCU\\Volatile Environment\\FibratusTestExpandSz"},
			"%SYSTEMROOT%\\fibratus",
		},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()

	defer func() {
		key.DeleteValue("FibratusTestDword")
		key.DeleteValue("FibratusTestQword")
		key.DeleteValue("FibratusTestSz")
		key.DeleteValue("FibratusTestMultiSz")
		key.DeleteValue("FibratusTestExpandSz")
	}()

	require.NoError(t, key.SetDWordValue("FibratusTestDword", 1))
	require.NoError(t, key.SetQWordValue("FibratusTestQword", 1000))
	require.NoError(t, key.SetStringValue("FibratusTestSz", "fibratus"))
	require.NoError(t, key.SetStringsValue("FibratusTestMultiSz", []string{"fibratus", "tracing"}))
	require.NoError(t, key.SetExpandStringValue("FibratusTestExpandSz", "%SYSTEMROOT%\\fibratus"))

	for i, tt := range tests {
		f := GetRegValue{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
}
