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

package eval

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/event"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

func TestIsFieldAccessible(t *testing.T) {
	var tests = []struct {
		a            Accessor
		e            *event.Event
		isAccessible bool
	}{
		{
			newEventAccessor(),
			&event.Event{Type: event.QueryDNS, Category: event.Net},
			true,
		},
		{
			newPSAccessor(nil),
			&event.Event{Type: event.CreateProcess, Category: event.Process},
			true,
		},
		{
			newPSAccessor(nil),
			&event.Event{PS: &ptypes.PS{}, Type: event.CreateFile, Category: event.File},
			true,
		},
		{
			newPSAccessor(nil),
			&event.Event{Type: event.SetThreadContext, Category: event.Thread},
			false,
		},
		{
			newThreadAccessor(),
			&event.Event{Type: event.SetThreadContext, Category: event.Thread},
			true,
		},
		{
			newThreadAccessor(),
			&event.Event{Type: event.CreateProcess, Category: event.Process, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newThreadAccessor(),
			&event.Event{Type: event.RegSetValue, Category: event.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newRegistryAccessor(),
			&event.Event{Type: event.RegSetValue, Category: event.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			true,
		},
		{
			newNetworkAccessor(),
			&event.Event{Type: event.RegSetValue, Category: event.Registry, Callstack: []callstack.Frame{{Addr: 0x7ffb5c1d0396, Offset: 0x61, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"}}},
			false,
		},
		{
			newNetworkAccessor(),
			&event.Event{Type: event.ConnectTCPv6, Category: event.Net},
			true,
		},
		{
			newDNSAccessor(),
			&event.Event{Type: event.ReplyDNS, Category: event.Net},
			true,
		},
		{
			newModuleAccessor(),
			&event.Event{Type: event.LoadModule, Category: event.Module},
			true,
		},
		{
			newMemAccessor(),
			&event.Event{Type: event.VirtualAlloc, Category: event.Mem},
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
