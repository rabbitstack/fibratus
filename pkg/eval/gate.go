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
)

// servesEvent reports whether the values of the source can be read from the
// event. A field of a source that can't serve the event isn't read at all, it
// evaluates to the default value. What decides is usually the category of the
// event, but it can also be the presence of the process state or the callstack.
// A source that the platform doesn't have serves no event.
//
// The gates are hand written, one switch per platform, in gate_windows.go and
// gate_linux.go.
func servesEvent(src fields.Source, e *event.Event) bool {
	if src == fields.SourceEvent {
		return true
	}
	return platformServesEvent(src, e)
}
