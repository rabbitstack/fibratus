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
	"golang.org/x/sys/unix"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

func platformServesEvent(src fields.Source, e *event.Event) bool {
	switch src {
	case fields.SourceProcess:
		return e.PS != nil || e.Category() == event.Process
	case fields.SourceThread:
		return e.IsCreateThread()
	case fields.SourceFile:
		return e.Category() == event.File
	case fields.SourceNetwork:
		return e.Category() == event.Network
	case fields.SourceMemory:
		return e.Category() == event.Memory
	default:
		return false
	}
}

// bestCaseEvent returns an event of the type that has everything a source
// may ask for besides the type: the process state, and the thread flag of clone.
func bestCaseEvent(t event.Type) *event.Event {
	e := &event.Event{Type: t, PS: &pstypes.PS{}}
	if t == event.Clone {
		e.Params = event.ParamsOf(event.NewParam(params.CloneFlags, params.Uint64, params.U64(unix.CLONE_THREAD)))
	}
	return e
}
