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

package event

import (
	"expvar"
)

// eventsEnqueued counts the number of events that are pushed to the queue
var eventsEnqueued = expvar.NewInt("eventsource.events.enqueued")

// Listener is the minimal interface that all event listeners need to implement.
type Listener interface {
	// ProcessEvent receives the event and returns a boolean value
	// indicating if the event should continue the processing journey.
	// In case any errors occur during processing, this method returns
	// the error and stops further event processing.
	ProcessEvent(*Event) (bool, error)
	// CanEnqueue indicates if the event listener is capable of
	// submitting the event to the output queue if the ProcessEvent
	// method returns true. In general, processors that merely
	// mutate or enrich event state, shouldn't influence event
	// queueing decisions.
	CanEnqueue() bool
}

// queue is the channel-backed data structure for
// pushing captured events and invoking listeners.
type queue struct {
	q               chan *Event
	listeners       []Listener
	stackEnrichment bool
	enqueueAlways   bool
}

// RegisterListener registers a new queue event listener. The listener
// is invoked before the event is pushed to the queue.
func (q *Queue) RegisterListener(listener Listener) {
	q.listeners = append(q.listeners, listener)
}

// Events returns the channel with all queued events.
func (q *Queue) Events() <-chan *Event { return q.q }

func (q *Queue) push(e *Event) error {
	var enqueue bool
	if q.enqueueAlways {
		enqueue = true
	}

	for _, listener := range q.listeners {
		enq, err := listener.ProcessEvent(e)
		if err != nil {
			return err
		}
		if listener.CanEnqueue() && enq {
			enqueue = true
		}
	}

	if enqueue || len(q.listeners) == 0 {
		q.q <- e
		eventsEnqueued.Add(1)
	}

	return nil
}
