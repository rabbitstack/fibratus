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
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// gateEvents returns the events that tell the gates apart: one for each
// event type, with and without the process state.
func gateEvents() map[string]*event.Event {
	evts := map[string]*event.Event{"empty": {}}
	for typ := event.Unknown + 1; typ < event.MaxEvent; typ++ {
		evts["bare "+typ.String()] = &event.Event{Type: typ}
		evts["ps "+typ.String()] = &event.Event{Type: typ, PS: &pstypes.PS{PID: 1}}
	}
	evts["clone thread"] = &event.Event{Type: event.Clone, Params: event.ParamsOf(event.NewParam(params.CloneFlags, params.Uint64, params.U64(0x10000)))}
	return evts
}

func TestLinuxGates(t *testing.T) {
	tests := []struct {
		name string
		evt  *event.Event
		want map[fields.Source]bool
	}{
		{"open", &event.Event{Type: event.Openat}, map[fields.Source]bool{fields.SourceFile: true}},
		{"connect", &event.Event{Type: event.Connect}, map[fields.Source]bool{fields.SourceNetwork: true}},
		{"mmap", &event.Event{Type: event.Mmap}, map[fields.Source]bool{fields.SourceMemory: true}},
		{"open with ps", &event.Event{Type: event.Openat, PS: &pstypes.PS{PID: 1}},
			map[fields.Source]bool{fields.SourceFile: true, fields.SourceProcess: true}},
		{"clone thread", gateEvents()["clone thread"],
			map[fields.Source]bool{fields.SourceThread: true, fields.SourceProcess: true}},
		{"clone process", &event.Event{Type: event.Clone, Params: event.ParamsOf(event.NewParam(params.CloneFlags, params.Uint64, params.U64(0)))},
			map[fields.Source]bool{fields.SourceProcess: true}},
	}
	sources := []fields.Source{fields.SourceProcess, fields.SourceThread, fields.SourceFile,
		fields.SourceNetwork, fields.SourceMemory, fields.SourceModule, fields.SourceRegistry, fields.SourcePE, fields.SourceDNS}
	for _, tt := range tests {
		for _, src := range sources {
			assert.Equal(t, tt.want[src], servesEvent(src, tt.evt), "%s serves %s", src, tt.name)
		}
	}
}
