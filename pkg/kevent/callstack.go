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
	"expvar"
	"github.com/gammazero/deque"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxDequeFlushPeriod specifies the maximum period
// for the events to reside in the deque.
var maxDequeFlushPeriod = 2 * time.Minute

// callstackFlushes computes overall callstack dequeue flushes
var callstackFlushes = expvar.NewInt("callstack.flushes")

// Frame describes a single stack frame.
type Frame struct {
	Addr           va.Address
	Offset         uint64
	AllocationSize uint64
	Symbol         string
	Module         string
	Protection     string
}

// IsUnbacked returns true if this frame is originated
// from unbacked memory section
func (f Frame) IsUnbacked() bool { return f.Module == "unbacked" }

// Callstack is a sequence of stack frames
// representing function executions.
type Callstack []Frame

// Init allocates the initial callstack capacity.
func (s *Callstack) Init(n int) {
	*s = make(Callstack, 0, n)
}

// PushFrame pushes a new from to the call stack.
func (s *Callstack) PushFrame(f Frame) {
	*s = append(*s, f)
}

// Depth returns the number of frames in the call stack.
func (s *Callstack) Depth() int { return len(*s) }

// Summary returns a sequence of module names for each stack frame.
func (s Callstack) Summary() string {
	var sb strings.Builder
	for i, frame := range s {
		if frame.IsUnbacked() {
			sb.WriteString("unbacked")
		} else {
			sb.WriteString(filepath.Base(frame.Module))
		}
		if i != len(s)-1 {
			sb.WriteRune('|')
		}
	}
	return sb.String()
}

func (s Callstack) String() string {
	var sb strings.Builder
	for i, frame := range s {
		sb.WriteString("0x")
		sb.WriteString(frame.Addr.String())
		sb.WriteString(" ")
		sb.WriteString(frame.Module)
		sb.WriteRune('!')
		if frame.Symbol != "" && frame.Symbol != "?" {
			sb.WriteString(frame.Symbol)
		} else {
			sb.WriteRune('?')
		}
		if frame.Offset != 0 {
			sb.WriteString("+0x")
			sb.WriteString(strconv.FormatUint(frame.Offset, 16))
		}
		if i != len(s)-1 {
			sb.WriteRune('|')
		}
	}
	return sb.String()
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
	mux sync.Mutex
}

// NewCallstackDecorator creates a new callstack decorator
// which receives the event queue for long-standing event
// flushing.
func NewCallstackDecorator(q *Queue) *CallstackDecorator {
	return &CallstackDecorator{q: q, deq: deque.New[*Kevent](100)}
}

// Push pushes a new event to the queue.
func (cd *CallstackDecorator) Push(e *Kevent) {
	cd.mux.Lock()
	defer cd.mux.Unlock()
	cd.deq.PushBack(e)
}

// Pop receives the stack walk event and pops the oldest
// originating event with the same pid,tid tuple formerly
// coined as stack identifier. The originating event is then
// decorated with callstack return addresses.
func (cd *CallstackDecorator) Pop(e *Kevent) *Kevent {
	cd.mux.Lock()
	defer cd.mux.Unlock()
	i := cd.deq.Index(func(evt *Kevent) bool { return evt.StackID() == e.StackID() })
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
	cd.mux.Lock()
	defer cd.mux.Unlock()
	if cd.deq.Len() == 0 {
		return nil
	}
	errs := make([]error, 0)
	for i := 0; i < cd.deq.Len(); i++ {
		evt := cd.deq.At(i)
		if time.Since(evt.Timestamp) < maxDequeFlushPeriod {
			continue
		}
		callstackFlushes.Add(1)
		err := cd.q.push(cd.deq.Remove(i))
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
