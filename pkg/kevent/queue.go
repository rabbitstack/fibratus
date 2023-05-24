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

package kevent

import "expvar"

// keventsEnqueued counts the number of events that are pushed to the queue
var keventsEnqueued = expvar.NewInt("kstream.kevents.enqueued")

// Listener is the minimal interface that all event listeners need to implement.
type Listener interface {
	// ProcessEvent receives the event and returns a boolean value
	// indicating if the event should continue the processing journey.
	// In case any errors occur during processing, this method returns
	// the error and stops further event processing.
	ProcessEvent(*Kevent) (bool, error)
}

// Queue is the channel-backed data structure for
// pushing captured events and invoking listeners.
type Queue struct {
	q         chan *Kevent
	listeners []Listener
}

// NewQueue constructs a new queue with the given channel size.
func NewQueue(size int) *Queue {
	return &Queue{q: make(chan *Kevent, size), listeners: make([]Listener, 0)}
}

// RegisterListener registers a new queue event listener. The listener
// is invoked before the event is pushed to the queue.
func (q *Queue) RegisterListener(listener Listener) {
	q.listeners = append(q.listeners, listener)
}

// Events returns the channel with all queued events.
func (q *Queue) Events() <-chan *Kevent { return q.q }

// Push pushes a new event to the channel. Prior to
// sending the event to the channel, all registered
// listeners are invoked. The event is sent to the
// channel if one of the listeners agrees so and no
// errors are thrown.
func (q *Queue) Push(e *Kevent) error {
	var enqueue bool
	for _, listener := range q.listeners {
		enq, err := listener.ProcessEvent(e)
		if err != nil {
			return err
		}
		if enq {
			enqueue = true
		}
	}
	if enqueue {
		q.q <- e
		keventsEnqueued.Add(1)
	}
	return nil
}
