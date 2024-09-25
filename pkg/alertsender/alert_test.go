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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
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
			NewAlertWithEvents("Credential discovery via VaultCmd.exe", "Suspicious vault enumeration via VaultCmd tool", nil, Normal, []*kevent.Kevent{{
				Type:     ktypes.CreateProcess,
				Category: ktypes.Process,
				Kparams: kevent.Kparams{
					kparams.Cmdline:     {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-fake.exe -k RPCSS"},
					kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost-fake.exe"}},
				Name: "CreateProcess",
				PID:  1023,
				PS: &pstypes.PS{
					Name:     "svchost.exe",
					Cmdline:  "C:\\Windows\\System32\\svchost.exe",
					Ppid:     345,
					Username: "SYSTEM",
					Domain:   "NT AUTHORITY",
					SID:      "S-1-5-18",
				},
			}}),
			true,
			"Credential discovery via VaultCmd.exe\n\nSuspicious vault enumeration via VaultCmd tool\n\nEvent #1:\n\n\t\tSeq: 0\n\t\tPid: 1023\n\t\tTid: 0\n\t\tType: CreateProcess\n\t\tCPU: 0\n\t\tName: CreateProcess\n\t\tCategory: process\n\t\tDescription: \n\t\tHost: ,\n\t\tTimestamp: 0001-01-01 00:00:00 +0000 UTC,\n\t\tKparams: cmdline➜ C:\\Windows\\system32\\svchost-fake.exe -k RPCSS, name➜ svchost-fake.exe,\n\t\tMetadata: ,\n\t    \n\t\tPid:  0\n\t\tPpid: 345\n\t\tName: svchost.exe\n\t\tCmdline: C:\\Windows\\System32\\svchost.exe\n\t\tExe:  \n\t\tCwd:  \n\t\tSID:  S-1-5-18\n\t\tUsername: SYSTEM\n\t\tDomain: NT AUTHORITY\n\t\tArgs: []\n\t\tSession ID: 0\n\t\tEnvs: map[]\n\t\t\n\t",
		},
		{
			NewAlertWithEvents("Credential discovery via VaultCmd.exe", "", nil, Normal, []*kevent.Kevent{{
				Type:     ktypes.CreateProcess,
				Category: ktypes.Process,
				Kparams: kevent.Kparams{
					kparams.Cmdline:     {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-fake.exe -k RPCSS"},
					kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost-fake.exe"}},
				Name: "CreateProcess",
				PID:  1023,
				PS: &pstypes.PS{
					Name:     "svchost.exe",
					Cmdline:  "C:\\Windows\\System32\\svchost.exe",
					Ppid:     345,
					Username: "SYSTEM",
					Domain:   "NT AUTHORITY",
					SID:      "S-1-5-18",
				},
			}}),
			true,
			"Credential discovery via VaultCmd.exe\n\nEvent #1:\n\n\t\tSeq: 0\n\t\tPid: 1023\n\t\tTid: 0\n\t\tType: CreateProcess\n\t\tCPU: 0\n\t\tName: CreateProcess\n\t\tCategory: process\n\t\tDescription: \n\t\tHost: ,\n\t\tTimestamp: 0001-01-01 00:00:00 +0000 UTC,\n\t\tKparams: cmdline➜ C:\\Windows\\system32\\svchost-fake.exe -k RPCSS, name➜ svchost-fake.exe,\n\t\tMetadata: ,\n\t    \n\t\tPid:  0\n\t\tPpid: 345\n\t\tName: svchost.exe\n\t\tCmdline: C:\\Windows\\System32\\svchost.exe\n\t\tExe:  \n\t\tCwd:  \n\t\tSID:  S-1-5-18\n\t\tUsername: SYSTEM\n\t\tDomain: NT AUTHORITY\n\t\tArgs: []\n\t\tSession ID: 0\n\t\tEnvs: map[]\n\t\t\n\t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			require.Equal(t, tt.wantString, tt.alert.String(tt.verbose))
		})
	}
}
