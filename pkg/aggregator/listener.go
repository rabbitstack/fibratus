/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package aggregator

import "github.com/rabbitstack/fibratus/pkg/kevent"

// Listener is the minimal interface that all aggregator listeners need to implement.
type Listener interface {
	// ProcessEvent receives the event and returns a boolean value
	// indicating if the event should be routed to the aggregator
	// output queue.
	ProcessEvent(*kevent.Kevent) bool
}
