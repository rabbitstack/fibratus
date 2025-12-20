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

// Queue is the channel-backed data structure for
// pushing captured events and invoking listeners.
type Queue struct {
	q               chan *Event
	listeners       []Listener
	decorator       *StackwalkDecorator
	stackEnrichment bool
	enqueueAlways   bool
}

// NewQueue constructs a new queue with the given channel size.
func NewQueue(size int, stackEnrichment bool, enqueueAlways bool) *Queue {
	q := &Queue{
		q:               make(chan *Event, size),
		listeners:       make([]Listener, 0),
		stackEnrichment: stackEnrichment,
		enqueueAlways:   enqueueAlways,
	}
	q.decorator = NewStackwalkDecorator(q)
	return q
}

// NewQueueWithChannel constructs a new queue with a custom channel.
func NewQueueWithChannel(ch chan *Event, stackEnrichment bool, enqueueAlways bool) *Queue {
	q := &Queue{
		q:               ch,
		listeners:       make([]Listener, 0),
		stackEnrichment: stackEnrichment,
		enqueueAlways:   enqueueAlways,
	}
	q.decorator = NewStackwalkDecorator(q)
	return q
}

// RegisterListener registers a new queue event listener. The listener
// is invoked before the event is pushed to the queue.
func (q *Queue) RegisterListener(listener Listener) {
	q.listeners = append(q.listeners, listener)
}

// Events returns the channel with all queued events.
func (q *Queue) Events() <-chan *Event { return q.q }

// Close closes the queue disposing allocated resources.
func (q *Queue) Close() { q.decorator.Stop() }

// Push pushes a new event to the channel. Prior to
// sending the event to the channel, all registered
// listeners are invoked. The event is sent to the
// channel if one of the listeners agrees so and no
// errors are thrown. If the event depends on the state
// of subsequent events, then we store it in the backlog
// cache. The event is fetched from the backlog cache if
// the matching event arrives, i.e. that backlog key holds
// the value that was used to index the delayed event in the
// backlog.
// It is also the responsibility of the event queue to perform
// callstack enrichment if enabled. We first
// check if the current event is eligible for stack
// enrichment. If such condition is given, the event
// is pushed into callstack decorator FIFO queue.
// The stack return addresses are stored inside StackWalk
// event which is published after the acting event.
// Then, the originating event is popped from the queue,
// enriched with callstack parameter and forwarded to the
// event queue.
func (q *Queue) Push(e *Event) error {
	if q.stackEnrichment {
		// store pending event for callstack enrichment
		if e.Type.CanEnrichStack() {
			q.decorator.Push(e)
			return nil
		}
		// decorate events with callstack return addresses
		if e.IsStackWalk() {
			e = q.decorator.Pop(e)
		}
	}
	// drop stack walk events
	if e.IsStackWalk() {
		return nil
	}
	return q.push(e)
}

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
	if q.stackEnrichment && e.IsTerminateThread() {
		id := uint64(e.Params.MustGetPid() + e.Params.MustGetTid())
		q.decorator.RemoveBucket(id)
	}
	if enqueue || len(q.listeners) == 0 {
		q.q <- e
		eventsEnqueued.Add(1)
	}
	return nil
}
