//go:build windows
// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package key

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"testing"
)

func init() {
	loggedSID = "S-1-5-21-2271034452-2606270099-984871569-500"
}

func TestFormatKey(t *testing.T) {
	var tests = []struct {
		nativeKey   string
		wantsKey    Key
		wantsSubkey string
	}{
		{
			`\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
			windows.HKEY_LOCAL_MACHINE,
			`SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
		},
		{
			`\Registry\Machine\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
			windows.HKEY_LOCAL_MACHINE,
			`SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
		},
		{
			`\REGISTRY\MACHINE`,
			windows.HKEY_LOCAL_MACHINE,
			``,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\Console`,
			windows.HKEY_CURRENT_USER,
			`Console`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes`,
			windows.HKEY_CURRENT_USER,
			`Software\Classes`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes\.all`,
			windows.HKEY_CURRENT_USER,
			`Software\Classes\.all`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500`,
			windows.HKEY_CURRENT_USER,
			``,
		},
		{
			`\REGISTRY\USER\S-1-5-9\Network`,
			windows.HKEY_USERS,
			`S-1-5-9\Network`,
		},
		{
			`\REGISTRY\USER`,
			windows.HKEY_USERS,
			``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.nativeKey, func(t *testing.T) {
			nativeKey := tt.nativeKey
			k, s := tt.wantsKey, tt.wantsSubkey
			key, subkey := Format(nativeKey)
			assert.Equal(t, k, key)
			assert.Equal(t, s, subkey)
		})
	}
}

func TestReadValue(t *testing.T) {
	var tests = []struct {
		key      Key
		subkey   string
		expected interface{}
	}{
		{
			CurrentUser,
			"Volatile Environment\\FibratusTestDword",
			uint64(1),
		},
		{
			CurrentUser,
			"Volatile Environment\\FibratusTestQword",
			uint64(1000),
		},
		{
			CurrentUser,
			"Volatile Environment\\FibratusTestSz",
			"fibratus",
		},
		{
			CurrentUser,
			"Volatile Environment\\\\FibratusTestSzSlash",
			"slash",
		},
		{
			CurrentUser,
			"Volatile Environment\\FibratusTestMultiSz",
			[]string{"fibratus", "edr"},
		},
		{
			CurrentUser,
			"Volatile Environment\\FibratusTestExpandSz",
			"%SYSTEMROOT%\\fibratus",
		},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()

	defer func() {
		_ = key.DeleteValue("FibratusTestDword")
		_ = key.DeleteValue("FibratusTestQword")
		_ = key.DeleteValue("FibratusTestSz")
		_ = key.DeleteValue("FibratusTestSzSlash")
		_ = key.DeleteValue("FibratusTestMultiSz")
		_ = key.DeleteValue("FibratusTestExpandSz")
	}()

	require.NoError(t, key.SetDWordValue("FibratusTestDword", 1))
	require.NoError(t, key.SetQWordValue("FibratusTestQword", 1000))
	require.NoError(t, key.SetStringValue("FibratusTestSz", "fibratus"))
	require.NoError(t, key.SetStringValue("\\FibratusTestSzSlash", "slash"))
	require.NoError(t, key.SetStringsValue("FibratusTestMultiSz", []string{"fibratus", "edr"}))
	require.NoError(t, key.SetExpandStringValue("FibratusTestExpandSz", "%SYSTEMROOT%\\fibratus"))

	for _, tt := range tests {
		t.Run(tt.subkey, func(t *testing.T) {
			_, val, err := tt.key.ReadValue(tt.subkey)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}
