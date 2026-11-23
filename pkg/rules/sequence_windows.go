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

package rules

import (
	"slices"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// expire drops the chains that contain the events of the process terminated by the event.
func (s *SequenceEvaluator) expire(evt *event.Event) {
	if !evt.IsTerminateProcess() {
		return
	}

	pid := evt.Params.GetPid()
	canExpire := func(e *event.Event, pid uint32) bool {
		// the chain can be dropped only if the remote process terminates
		if e.IsCreateRemoteThread() {
			return e.Params.GetPid() == pid
		}
		// final stage holds a CreateProcess event. Only expire
		// if the spawned pid matches the terminating pid

		// Everything else
		return e.PID == pid
	}

	for _, stage := range s.lookups {
		for _, chain := range stage {
			if slices.ContainsFunc(chain.events,
				func(evt *event.Event) bool { return canExpire(evt, pid) }) {
				s.drop(chain)
			}
		}
	}
}
