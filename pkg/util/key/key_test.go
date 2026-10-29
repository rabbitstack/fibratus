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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func init() {
	loggedSID = "S-1-5-21-2271034452-2606270099-984871569-500"
}

func TestSplitKey(t *testing.T) {
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
			`\REGISTRY\USER`,
			windows.HKEY_USERS,
			``,
		},
		{
			`\REGISTRY\USER\S-1-5-9\Network`,
			windows.HKEY_USERS,
			`S-1-5-9\Network`,
		},
		{
			`\REGISTRY\A`,
			Invalid,
			`\REGISTRY\A`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.nativeKey, func(t *testing.T) {
			nativeKey := tt.nativeKey
			k, s := tt.wantsKey, tt.wantsSubkey
			root, subkey := splitKey(nativeKey)
			assert.Equal(t, k, root)
			assert.Equal(t, s, subkey)
		})
	}
}

func TestFormat(t *testing.T) {
	var tests = []struct {
		nativeKey    string
		formattedKey string
	}{
		{
			`\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
			`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
		},
		{
			`\Registry\Machine\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
			`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`,
		},
		{
			`\REGISTRY\MACHINE`,
			`HKEY_LOCAL_MACHINE`,
		},
		{
			`\REGISTRY\USER`,
			`HKEY_USERS`,
		},
		{
			`\REGISTRY\USER\S-1-5-9\Network`,
			`HKEY_USERS\S-1-5-9\Network`,
		},
		{
			`\REGISTRY\A`,
			`\REGISTRY\A`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\Console`,
			`HKEY_CURRENT_USER\Console`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes`,
			`HKEY_CURRENT_USER\Software\Classes`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`,
			`HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes\.all`,
			`HKEY_CURRENT_USER\Software\Classes\.all`,
		},
		{
			`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500`,
			`HKEY_CURRENT_USER`,
		},
		{
			`\REGISTRY\USER\S-1-5-9\Network`,
			`HKEY_USERS\S-1-5-9\Network`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.nativeKey, func(t *testing.T) {
			assert.Equal(t, tt.formattedKey, Format(tt.nativeKey))
		})
	}
}

func TestSplitKeyKeepsSID(t *testing.T) {
	root, sub := splitKey(`\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Fibratus`)
	assert.Equal(t, Users, root)
	assert.Equal(t, `S-1-5-21-1-2-3-1001\Software\Fibratus`, sub)
}

func TestReadValue(t *testing.T) {
	var tests = []struct {
		path     string
		value    string
		expected any
	}{
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\FibratusTestDword", getLoggedSID()),
			"FibratusTestDword",
			uint64(1),
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\FibratusTestQword", getLoggedSID()),
			"FibratusTestQword",
			uint64(1000),
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\FibratusTestSz", getLoggedSID()),
			"FibratusTestSz",
			"fibratus",
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\\\FibratusTestSzSlash", getLoggedSID()),
			"\\FibratusTestSzSlash",
			"slash",
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\FibratusTestMultiSz", getLoggedSID()),
			"FibratusTestMultiSz",
			[]string{"fibratus", "edr"},
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\FibratusTestExpandSz", getLoggedSID()),
			"FibratusTestExpandSz",
			"%SYSTEMROOT%\\fibratus",
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\UDP Query User{108C2D9B-A047-4E78-B337-BAFC7D9273AB}C:\\users\\admin\\appdata\\local\\temp\\go-build49437379\\b001\\kstream.test.exe", getLoggedSID()),
			"UDP Query User{108C2D9B-A047-4E78-B337-BAFC7D9273AB}C:\\users\\admin\\appdata\\local\\temp\\go-build49437379\\b001\\kstream.test.exe",
			`path`,
		},
		{
			fmt.Sprintf("\\REGISTRY\\USER\\%s\\Volatile Environment\\C:\\Program Files\\Java\\jre1.8.0_311\\bin\\javaws.exe.FriendlyAppName", getLoggedSID()),
			"C:\\Program Files\\Java\\jre1.8.0_311\\bin\\javaws.exe.FriendlyAppName",
			"javaws.exe",
		},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()

	defer func() {
		_ = key.DeleteValue("FibratusTestDword")
		_ = key.DeleteValue("FibratusTestQword")
		_ = key.DeleteValue("FibratusTestSz")
		_ = key.DeleteValue("\\FibratusTestSzSlash")
		_ = key.DeleteValue("FibratusTestMultiSz")
		_ = key.DeleteValue("FibratusTestExpandSz")
		_ = key.DeleteValue("UDP Query User{108C2D9B-A047-4E78-B337-BAFC7D9273AB}C:\\users\\admin\\appdata\\local\\temp\\go-build49437379\\b001\\kstream.test.exe")
		_ = key.DeleteValue("C:\\Program Files\\Java\\jre1.8.0_311\\bin\\javaws.exe.FriendlyAppName")
	}()

	require.NoError(t, key.SetDWordValue("FibratusTestDword", 1))
	require.NoError(t, key.SetQWordValue("FibratusTestQword", 1000))
	require.NoError(t, key.SetStringValue("FibratusTestSz", "fibratus"))
	require.NoError(t, key.SetStringValue("\\FibratusTestSzSlash", "slash"))
	require.NoError(t, key.SetStringsValue("FibratusTestMultiSz", []string{"fibratus", "edr"}))
	require.NoError(t, key.SetExpandStringValue("FibratusTestExpandSz", "%SYSTEMROOT%\\fibratus"))
	require.NoError(t, key.SetStringValue("UDP Query User{108C2D9B-A047-4E78-B337-BAFC7D9273AB}C:\\users\\admin\\appdata\\local\\temp\\go-build49437379\\b001\\kstream.test.exe", "path"))
	require.NoError(t, key.SetStringValue("C:\\Program Files\\Java\\jre1.8.0_311\\bin\\javaws.exe.FriendlyAppName", "javaws.exe"))

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, val, err := ReadValue(tt.path, tt.value)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}
