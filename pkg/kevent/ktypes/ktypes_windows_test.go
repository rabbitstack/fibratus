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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"syscall"
	"testing"
)

func TestPack(t *testing.T) {
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

	assert.Equal(t, byte(0x1), CreateProcess[16])

	kt := Pack(syscall.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}, 1)
	assert.Equal(t, CreateProcess, kt)

	kt = Pack(syscall.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}, 2)
	assert.NotEqual(t, CreateProcess, kt)
	assert.Equal(t, TerminateProcess, kt)

	switch kt {
	case TerminateProcess:
	default:
		t.Fatal("expected TerminateProcess kernel event")
	}
}

func TestKtypeExists(t *testing.T) {
	require.True(t, AcceptTCPv4.Exists())
	require.True(t, AcceptTCPv6.Exists())
}
