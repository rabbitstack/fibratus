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

package ktypes

import (
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"testing"
)

func TestPackAllBytes(t *testing.T) {
	assert.Equal(t, byte(0x3d), CreateProcess[0])
	assert.Equal(t, byte(0x6f), CreateProcess[1])
	assert.Equal(t, byte(0xa8), CreateProcess[2])
	assert.Equal(t, byte(0xd0), CreateProcess[3])

	assert.Equal(t, byte(0xfe), CreateProcess[4])
	assert.Equal(t, byte(0x05), CreateProcess[5])

	assert.Equal(t, byte(0x11), CreateProcess[6])
	assert.Equal(t, byte(0xd0), CreateProcess[7])

	assert.Equal(t, byte(0x9d), CreateProcess[8])
	assert.Equal(t, byte(0xda), CreateProcess[9])
	assert.Equal(t, byte(0x0), CreateProcess[10])
	assert.Equal(t, byte(0xc0), CreateProcess[11])
	assert.Equal(t, byte(0x4f), CreateProcess[12])
	assert.Equal(t, byte(0xd7), CreateProcess[13])
	assert.Equal(t, byte(0xba), CreateProcess[14])
	assert.Equal(t, byte(0x7c), CreateProcess[15])
	assert.Equal(t, byte(0x0), CreateProcess[16])
	assert.Equal(t, byte(0x1), CreateProcess[17])

	assert.Equal(t, byte(0x0b), QueryDNS[16])
	assert.Equal(t, byte(0xbe), QueryDNS[17])
}

func TestKtypeComparision(t *testing.T) {
	var tests = []struct {
		name  string
		ktyp  Ktype
		wants Ktype
	}{
		{
			"equals CreateProcess",
			pack(windows.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}, 1),
			CreateProcess,
		},
		{
			"equals TerminateProcess",
			pack(windows.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}, 2),
			TerminateProcess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lhs, rhs := tt.ktyp, tt.wants
			assert.Equal(t, lhs, rhs)
		})
	}
}

func TestNewFromEventRecord(t *testing.T) {
	assert.Equal(t, CreateProcess, NewFromEventRecord(&etw.EventRecord{
		Header: etw.EventHeader{
			ProviderID: windows.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}},
			EventDescriptor: etw.EventDescriptor{
				Opcode: 1,
			},
		},
	}))
	assert.Equal(t, OpenProcess, NewFromEventRecord(&etw.EventRecord{
		Header: etw.EventHeader{
			ProviderID: windows.GUID{Data1: 0xe02a841c, Data2: 0x75a3, Data3: 0x4fa7, Data4: [8]byte{0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}},
			EventDescriptor: etw.EventDescriptor{
				ID: 5,
			},
		},
	}))
}

func TestKtypeExists(t *testing.T) {
	require.True(t, AcceptTCPv4.Exists())
	require.True(t, AcceptTCPv6.Exists())
}

func TestGUIDAndHookIDFromKtype(t *testing.T) {
	var tests = []struct {
		ktype  Ktype
		opcode uint16
		guid   windows.GUID
	}{
		{
			LoadImage,
			10,
			windows.GUID{Data1: 0x2cb15d1d, Data2: 0x5fc1, Data3: 0x11d2, Data4: [8]byte{0xab, 0xe1, 0x0, 0xa0, 0xc9, 0x11, 0xf5, 0x18}},
		},
		{
			WriteFile,
			68,
			windows.GUID{Data1: 0x90cbdc39, Data2: 0x4a3e, Data3: 0x11d1, Data4: [8]byte{0x84, 0xf4, 0x0, 0x0, 0xf8, 0x04, 0x64, 0xe3}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.ktype.String(), func(t *testing.T) {
			assert.Equal(t, tt.guid.String(), tt.ktype.GUID().String())
			assert.Equal(t, tt.opcode, tt.ktype.HookID())
		})
	}
}

func TestCanArriveOutOfOrder(t *testing.T) {
	assert.False(t, RegSetValue.CanArriveOutOfOrder())
	assert.False(t, VirtualAlloc.CanArriveOutOfOrder())
	assert.True(t, OpenProcess.CanArriveOutOfOrder())
}
