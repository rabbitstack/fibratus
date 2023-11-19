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

import (
	"github.com/gammazero/deque"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"time"
)

// maxDequeFlushPeriod specifies the maximum period in seconds for
// the events to reside in the deque.
const maxDequeFlushPeriod = 2

// Frame describes a single stack frame.
type Frame struct {
	Addr   uint64
	Symbol string
	Module string
}

func (f Frame) IsUnbacked() bool { return f.Module == "?" }

// Callstack is a collection of stack frames.
type Callstack []Frame

// Init allocates the initial callstack length.
func (s *Callstack) Init(n int) {
	*s = make(Callstack, n)
}

// ContainsUnbacked returns true if there is a frame
// pertaining to the function call initiated from the
// unbacked memory section.
func (s Callstack) ContainsUnbacked() bool {
	for _, frame := range s {
		if frame.IsUnbacked() {
			return true
		}
	}
	return false
}

// CallstackDecorator maintains a FIFO queue where events
// eligible for stack enrichment are queued. Upon arrival
// of the respective stack walk event, the acting event is
// popped from the queue and enriched with return addresses
// which are later subject to symbolization.
type CallstackDecorator struct {
	deq *deque.Deque[*Kevent]
	q   *Queue
}

// NewCallstackDecorator creates a new callstack decorator
// which receives the event queue for long-standing event
// flushing.
func NewCallstackDecorator(q *Queue) *CallstackDecorator {
	return &CallstackDecorator{q: q, deq: deque.New[*Kevent]()}
}

// Push pushes a new event to the queue.
func (cd *CallstackDecorator) Push(e *Kevent) {
	cd.deq.PushBack(e)
}

// Pop receives the stack walk event and pops the oldest
// originating event with the same pid,tid tuple formerly
// coined as stack identifier. The originating event is then
// decorated with callstack return addresses.
func (cd *CallstackDecorator) Pop(e *Kevent) *Kevent {
	i := cd.deq.RIndex(func(evt *Kevent) bool { return evt.StackID() == e.StackID() })
	if i == -1 {
		return e
	}
	evt := cd.deq.Remove(i)
	callstack := e.Kparams.MustGetSlice(kparams.Callstack)
	evt.AppendParam(kparams.Callstack, kparams.Slice, callstack)
	return evt
}

// Flush pushes events to the event queue if they have
// been living in the deque more than the maximum allowed
// flush period.
func (cd *CallstackDecorator) Flush() []error {
	if cd.deq.Len() == 0 {
		return nil
	}
	errs := make([]error, 0)
	for i := 0; i < cd.deq.Len(); i++ {
		evt := cd.deq.At(i)
		if evt.Timestamp.Sub(time.Now()).Seconds() > maxDequeFlushPeriod {
			err := cd.q.push(cd.deq.Remove(i))
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}
