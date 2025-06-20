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

package alertsender

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAlertString(t *testing.T) {
	var tests = []struct {
		alert      Alert
		verbose    bool
		wantString string
	}{
		{
			NewAlert("Credential discovery via VaultCmd.exe", "", nil, Normal),
			false,
			"Credential discovery via VaultCmd.exe",
		},
		{
			NewAlert("Credential discovery via VaultCmd.exe", "Suspicious vault enumeration via VaultCmd tool", nil, Normal),
			false,
			"Credential discovery via VaultCmd.exe\n\nSuspicious vault enumeration via VaultCmd tool",
		},
		{
			NewAlertWithEvents("Credential discovery via VaultCmd.exe", "Suspicious vault enumeration via VaultCmd tool", nil, Normal, []*event.Event{{
				Type:     event.CreateProcess,
				Category: event.Process,
				Params: event.Params{
					params.Cmdline:     {Name: params.Cmdline, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\svchost-fake.exe -k RPCSS"},
					params.ProcessName: {Name: params.ProcessName, Type: params.AnsiString, Value: "svchost-fake.exe"}},
				Name: "CreateProcess",
				PID:  1023,
				PS: &pstypes.PS{
					Name:                "svchost.exe",
					Cmdline:             "C:\\Windows\\System32\\svchost.exe",
					Ppid:                345,
					Username:            "SYSTEM",
					Domain:              "NT AUTHORITY",
					SID:                 "S-1-5-18",
					TokenIntegrityLevel: "HIGH",
				},
			}}),
			true,
			"Credential discovery via VaultCmd.exe\n\nSuspicious vault enumeration via VaultCmd tool\n\nSeverity: low\n\nSystem event involved in this alert:\n\n\tEvent #1:\n\n\t\tSeq: 0\n\t\tPid: 1023\n\t\tTid: 0\n\t\tName: CreateProcess\n\t\tCategory: process\n\t\tHost: \n\t\tTimestamp: 0001-01-01 00:00:00 +0000 UTC\n\t\tParameters: cmdline➜ C:\\Windows\\system32\\svchost-fake.exe -k RPCSS, name➜ svchost-fake.exe\n    \n\t\tPid:  0\n\t\tPpid: 345\n\t\tName: svchost.exe\n\t\tCmdline: C:\\Windows\\System32\\svchost.exe\n\t\tExe: \n\t\tCwd: \n\t\tSID: S-1-5-18\n\t\tIntegrity level: HIGH\n\t\tUsername: SYSTEM\n\t\tDomain: NT AUTHORITY\n\t\tArgs: []\n\t\tSession ID: 0\n\t\tAncestors: \n\t\n",
		},
		{
			NewAlertWithEvents("Credential discovery via VaultCmd.exe", "", nil, Normal, []*event.Event{{
				Type:     event.CreateProcess,
				Category: event.Process,
				Params: event.Params{
					params.Cmdline:     {Name: params.Cmdline, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\svchost-fake.exe -k RPCSS"},
					params.ProcessName: {Name: params.ProcessName, Type: params.AnsiString, Value: "svchost-fake.exe"}},
				Name: "CreateProcess",
				PID:  1023,
				PS: &pstypes.PS{
					Name:                "svchost.exe",
					Cmdline:             "C:\\Windows\\System32\\svchost.exe",
					Ppid:                345,
					Username:            "SYSTEM",
					Domain:              "NT AUTHORITY",
					SID:                 "S-1-5-18",
					TokenIntegrityLevel: "HIGH",
				},
			}}),
			true,
			"Credential discovery via VaultCmd.exe\n\nSeverity: low\n\nSystem event involved in this alert:\n\n\tEvent #1:\n\n\t\tSeq: 0\n\t\tPid: 1023\n\t\tTid: 0\n\t\tName: CreateProcess\n\t\tCategory: process\n\t\tHost: \n\t\tTimestamp: 0001-01-01 00:00:00 +0000 UTC\n\t\tParameters: cmdline➜ C:\\Windows\\system32\\svchost-fake.exe -k RPCSS, name➜ svchost-fake.exe\n    \n\t\tPid:  0\n\t\tPpid: 345\n\t\tName: svchost.exe\n\t\tCmdline: C:\\Windows\\System32\\svchost.exe\n\t\tExe: \n\t\tCwd: \n\t\tSID: S-1-5-18\n\t\tIntegrity level: HIGH\n\t\tUsername: SYSTEM\n\t\tDomain: NT AUTHORITY\n\t\tArgs: []\n\t\tSession ID: 0\n\t\tAncestors: \n\t\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			require.Equal(t, tt.wantString, tt.alert.String(tt.verbose))
		})
	}
}
