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

package filter

import (
	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestNarrowAccessors(t *testing.T) {
	var tests = []struct {
		f                 Filter
		expectedAccessors int
	}{
		{
			New(`ps.name = 'cmd.exe' and kevt.name = 'CreateProcess' or kevt.name in ('TerminateProcess', 'CreateFile')`, cfg),
			2,
		},
		{
			New(`foreach(ps._modules, $mod, $mod.path = 'C:\\Windows\\System32')`, cfg),
			1,
		},
		{
			New(`handle.type = 'Section' and pe.nsections > 1 and kevt.name = 'CreateHandle'`, cfg),
			3,
		},
		{
			New(`sequence |kevt.name = 'CreateProcess'| as e1 |kevt.name = 'CreateFile' and file.name = $e1.ps.exe |`, cfg),
			3,
		},
		{
			New(`base(file.name) = 'kernel32.dll'`, cfg),
			1,
		},
	}

	var pea *peAccessor

	for i, tt := range tests {
		require.NoError(t, tt.f.Compile())
		naccessors := len(tt.f.(*filter).accessors)
		if tt.expectedAccessors != naccessors {
			t.Errorf("%d. accessors mismatch: exp=%d got=%d", i, tt.expectedAccessors, naccessors)
		}
		for _, a := range tt.f.(*filter).accessors {
			if reflect.TypeOf(a) == reflect.TypeOf(&peAccessor{}) {
				pea = a.(*peAccessor)
			}
		}
	}
	// check if fields are set in the accessor
	require.NotNil(t, pea)
	assert.Len(t, pea.fields, 3)
}

func TestIsFieldAccessible(t *testing.T) {
	var tests = []struct {
		a            Accessor
		e            *kevent.Kevent
		isAccessible bool
	}{
		{
			newKevtAccessor(),
			&kevent.Kevent{Type: ktypes.QueryDNS, Category: ktypes.Net},
			true,
		},
		{
			newPSAccessor(nil),
			&kevent.Kevent{Type: ktypes.CreateProcess, Category: ktypes.Process},
			true,
		},
		{
			newPSAccessor(nil),
			&kevent.Kevent{PS: &ptypes.PS{}, Type: ktypes.CreateFile, Category: ktypes.File},
			true,
		},
		{
			newPSAccessor(nil),
			&kevent.Kevent{Type: ktypes.SetThreadContext, Category: ktypes.Thread},
			false,
		},
		{
			newThreadAccessor(),
			&kevent.Kevent{Type: ktypes.SetThreadContext, Category: ktypes.Thread},
			true,
		},
		{
			newThreadAccessor(),
			&kevent.Kevent{Type: ktypes.CreateProcess, Category: ktypes.Process, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newThreadAccessor(),
			&kevent.Kevent{Type: ktypes.RegSetValue, Category: ktypes.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newRegistryAccessor(),
			&kevent.Kevent{Type: ktypes.RegSetValue, Category: ktypes.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newNetworkAccessor(),
			&kevent.Kevent{Type: ktypes.RegSetValue, Category: ktypes.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			false,
		},
		{
			newNetworkAccessor(),
			&kevent.Kevent{Type: ktypes.ConnectTCPv6, Category: ktypes.Net},
			true,
		},
		{
			newDNSAccessor(),
			&kevent.Kevent{Type: ktypes.ReplyDNS, Category: ktypes.Net},
			true,
		},
		{
			newImageAccessor(),
			&kevent.Kevent{Type: ktypes.LoadImage, Category: ktypes.Image},
			true,
		},
		{
			newMemAccessor(),
			&kevent.Kevent{Type: ktypes.VirtualAlloc, Category: ktypes.Mem},
			true,
		},
	}

	for i, tt := range tests {
		isAccessible := tt.a.IsFieldAccessible(tt.e)
		if tt.isAccessible != isAccessible {
			t.Errorf("%d. accessors is field accessible condition mismatch: exp=%t got=%t", i, tt.isAccessible, isAccessible)
		}
	}
}
