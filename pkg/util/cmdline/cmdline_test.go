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

package cmdline

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	var tests = []struct {
		cmdline string
		wantLen int
		wantExe string
	}{
		{
			`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler  "--database=Crashpad" "--metrics-dir=User Data" --max-uploads=5`,
			5,
			`C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`,
		},
		{
			`svchost.exe "-k netsvcs" -s UserManager`,
			4,
			`svchost.exe`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.cmdline, func(t *testing.T) {
			args := Split(tt.cmdline)
			require.Len(t, args, tt.wantLen)
			require.Equal(t, tt.wantExe, args[0])
		})
	}
}

func TestCmdline(t *testing.T) {
	require.NoError(t, os.Setenv("SystemRoot", "C:\\Windows"))
	var tests = []struct {
		cmdline     string
		wantExeline string
		wantCmdline string
	}{
		{
			`\SystemRoot\System32\smss.exe`,
			`C:\Windows\System32\smss.exe`,
			`C:\Windows\System32\smss.exe`,
		},
		{
			`%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16`,
			`C:\Windows\system32\csrss.exe`,
			`C:\Windows\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16`,
		},
		{
			`winlogon.exe`,
			`C:\Windows\System32\winlogon.exe`,
			`C:\Windows\System32\winlogon.exe`,
		},
		{
			`\??\C:\WINDOWS\system32\lsaiso.exe`,
			`C:\WINDOWS\system32\lsaiso.exe`,
			`C:\WINDOWS\system32\lsaiso.exe`,
		},
		{
			`"fontdrvhost.exe"`,
			`C:\Windows\System32\fontdrvhost.exe`,
			`C:\Windows\System32\fontdrvhost.exe`,
		},
		{
			`"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.16.10261.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe" Microsoft.WindowsTerminal_1.16.10261.0_x64__8wekyb3d8bbweApp`,
			`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.16.10261.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe`,
			`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.16.10261.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe Microsoft.WindowsTerminal_1.16.10261.0_x64__8wekyb3d8bbweApp`,
		},
		{
			`C:\WINDOWS\system32\svchost.exe -k RPCSS -p`,
			`C:\WINDOWS\system32\svchost.exe`,
			`C:\WINDOWS\system32\svchost.exe -k RPCSS -p`,
		},
		{
			`"C:\Program Files\Conexant\SAII\CxUtilSvc.exe"`,
			`C:\Program Files\Conexant\SAII\CxUtilSvc.exe`,
			`C:\Program Files\Conexant\SAII\CxUtilSvc.exe`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.cmdline, func(t *testing.T) {
			cmdline := New(tt.cmdline).
				CleanExe().
				ExpandSystemRoot().
				CompleteSysProc(strings.Trim(tt.cmdline, `""`))
			assert.Equal(t, tt.wantCmdline, cmdline.String())
			assert.Equal(t, tt.wantExeline, cmdline.Exeline())
		})
	}
}
