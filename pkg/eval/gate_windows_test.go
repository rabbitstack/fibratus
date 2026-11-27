/*
 * Copyright 2026 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// gateEvents returns the events that tell the gates apart: one for each
// event type, with and without the process state and the callstack.
func gateEvents() map[string]*event.Event {
	cs := callstack.Callstack{{PID: 1, Addr: 0x1000, Module: `C:\Windows\System32\ntdll.dll`}}
	evts := map[string]*event.Event{"empty": {}}
	for typ := event.Unknown + 1; typ < event.MaxEvent; typ++ {
		evts["bare "+typ.String()] = &event.Event{Type: typ}
		evts["ps "+typ.String()] = &event.Event{Type: typ, PS: &pstypes.PS{PID: 1}}
		evts["callstack "+typ.String()] = &event.Event{Type: typ, Callstack: cs}
	}
	return evts
}

func TestWindowsGates(t *testing.T) {
	cs := callstack.Callstack{{PID: 1, Addr: 0x1000}}
	tests := []struct {
		name string
		evt  *event.Event
		want map[fields.Source]bool
	}{
		{"create file", &event.Event{Type: event.CreateFile}, map[fields.Source]bool{fields.SourceFile: true}},
		{"registry", &event.Event{Type: event.RegCreateKey}, map[fields.Source]bool{fields.SourceRegistry: true}},
		{"load module", &event.Event{Type: event.LoadModule},
			map[fields.Source]bool{fields.SourceModule: true, fields.SourcePE: true}},
		{"dns", &event.Event{Type: event.QueryDNS}, map[fields.Source]bool{fields.SourceDNS: true}},
		{"memory", &event.Event{Type: event.VirtualAlloc}, map[fields.Source]bool{fields.SourceMemory: true}},
		{"file with ps", &event.Event{Type: event.CreateFile, PS: &pstypes.PS{PID: 1}},
			map[fields.Source]bool{fields.SourceFile: true, fields.SourceProcess: true, fields.SourcePE: true}},
		{"file with callstack", &event.Event{Type: event.CreateFile, Callstack: cs},
			map[fields.Source]bool{fields.SourceFile: true, fields.SourceThread: true}},
	}
	sources := []fields.Source{fields.SourceProcess, fields.SourceThread, fields.SourceFile, fields.SourceNetwork,
		fields.SourceMemory, fields.SourceModule, fields.SourceRegistry, fields.SourcePE, fields.SourceDNS}
	for _, tt := range tests {
		for _, src := range sources {
			assert.Equal(t, tt.want[src], servesEvent(src, tt.evt), "%s serves %s", src, tt.name)
		}
	}
}
