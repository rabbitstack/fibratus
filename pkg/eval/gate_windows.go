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
)

func platformServesEvent(src fields.Source, e *event.Event) bool {
	switch src {
	case fields.SourceProcess:
		return e.PS != nil || e.Category() == event.Process
	case fields.SourcePE:
		return e.PS != nil || e.IsLoadModule()
	case fields.SourceThread:
		return !e.Callstack.IsEmpty() || e.Category() == event.Thread
	case fields.SourceFile:
		return e.Category() == event.File
	case fields.SourceModule:
		return e.Category() == event.Module
	case fields.SourceRegistry:
		return e.Category() == event.Registry
	case fields.SourceNetwork:
		return e.Category() == event.Network
	case fields.SourceMemory:
		return e.Category() == event.Memory
	case fields.SourceDNS:
		return e.Subcategory() == event.DNS
	default:
		return false
	}
}

// bestCaseEvent returns an event of the type that has everything a source
// may ask for besides the type: the process state and the callstack.
func bestCaseEvent(t event.Type) *event.Event {
	return &event.Event{Type: t, PS: &pstypes.PS{}, Callstack: callstack.Callstack{{}}}
}
