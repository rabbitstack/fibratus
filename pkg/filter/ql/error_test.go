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

package ql

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestParseError(t *testing.T) {
	expr := `kevt.name in ('RegCreateKey', 'RegDeleteKey', 'RegSetValue', 'RegDeleteValue')
	        and
	     registry.key.name icontains
			(
	          CurrentVersion\\Run',
	          'Policies\\Explorer\\Run',
	          'Group Policy\\Scripts',
	          'Windows\\System\\Scripts',
	          'CurrentVersion\\Windows\\Load',
	          'CurrentVersion\\Windows\\Run',
	          'CurrentVersion\\Winlogon\\Shell',
	          'CurrentVersion\\Winlogon\\System',
	          'UserInitMprLogonScript'
	        )
	        or
	     registry.key.name istartswith
	        (
	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify',
	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit',
	          'HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32',
	          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute',
	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'
	        )
	        or
	     registry.key.name iendswith
	        (
	          'user shell folders\\startup'
	        )`
	expected := `kevt.name in ('RegCreateKey', 'RegDeleteKey', 'RegSetValue', 'RegDeleteValue')
	        and
	     registry.key.name icontains
			(
	          CurrentVersion\\Run',
╭─────────────^
|
|	          'Policies\\Explorer\\Run',
|	          'Group Policy\\Scripts',
|	          'Windows\\System\\Scripts',
|	          'CurrentVersion\\Windows\\Load',
|	          'CurrentVersion\\Windows\\Run',
|	          'CurrentVersion\\Winlogon\\Shell',
|	          'CurrentVersion\\Winlogon\\System',
|	          'UserInitMprLogonScript'
|	        )
|	        or
|	     registry.key.name istartswith
|	        (
|	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify',
|	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
|	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit',
|	          'HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32',
|	          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute',
|	          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'
|	        )
|	        or
|	     registry.key.name iendswith
|	        (
|	          'user shell folders\\startup'
|	        )
|
╰─────────────────── expected field, bound field, string, number, bool, ip, function`

	e := newParseError("[", []string{"field, bound field, string, number, bool, ip, function"}, 145, expr)
	require.Equal(t, expected, e.Error())

	expr = `ps.name = 'cmd.exe' aand ps.cmdline contains 'ss'`
	e = newParseError("[", []string{"operator"}, 20, expr)

	expected1 := `
ps.name = 'cmd.exe' aand ps.cmdline contains 'ss'
╭───────────────────^
|
|
╰─────────────────── expected operator`
	require.Equal(t, strings.TrimSpace(expected1), e.Error())
}
