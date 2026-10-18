/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import "github.com/rabbitstack/fibratus/pkg/event"

// EventHandler represents a handler for all events sent by the probe.
type EventHandler interface {
	HandleEvent(*event.Event) error
	ID() string
}

// EventConsumerHandler represents a handler for the subset of events sent by the probe.
// The consumer handler makes a copy of the event upon receipt as it might be recycled
// from the ring pool.
type EventConsumerHandler interface {
	ID() string
	ChanSize() int
	HandleEvent(*event.Event) error
	EventTypes() []event.Type
}
