/*
 * Copyright 2021-present by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// maxDequeFlushPeriod specifies the maximum period
// for the events to reside in the queue.
var maxDequeFlushPeriod = time.Second * 30

// flusherInterval specifies the interval for the queue flushing.
var flusherInterval = time.Second * 5

// callstackFlushes computes overall callstack dequeue flushes
var callstackFlushes = expvar.NewInt("callstack.flushes")

// StackwalkDecorator maintains a FIFO queue where events
// eligible for stack enrichment are queued. Upon arrival
// of the respective stack walk event, the acting event is
// popped from the queue and enriched with return addresses
// which are later subject to symbolization.
type StackwalkDecorator struct {
	buckets map[uint64][]*Kevent
	q       *Queue
	mux     sync.Mutex

	flusher *time.Ticker
	quit    chan struct{}
}

// NewStackwalkDecorator creates a new callstack return
// addresses decorator which receives the event queue
// for long-standing event flushing.
func NewStackwalkDecorator(q *Queue) *StackwalkDecorator {
	s := &StackwalkDecorator{
		q:       q,
		buckets: make(map[uint64][]*Kevent),
		flusher: time.NewTicker(flusherInterval),
		quit:    make(chan struct{}, 1),
	}

	go s.doFlush()

	return s
}

// Push pushes a new event to the queue.
func (s *StackwalkDecorator) Push(e *Kevent) {
	s.mux.Lock()
	defer s.mux.Unlock()

	// append the event to the bucket indexed by stack id
	id := e.StackID()
	q, ok := s.buckets[id]
	if !ok {
		s.buckets[id] = []*Kevent{e}
	} else {
		s.buckets[id] = append(q, e)
	}
}

// Pop receives the stack walk event and pops the oldest
// originating event with the same pid,tid tuple formerly
// coined as stack identifier. The originating event is then
// decorated with callstack return addresses.
func (s *StackwalkDecorator) Pop(e *Kevent) *Kevent {
	s.mux.Lock()
	defer s.mux.Unlock()

	id := e.StackID()
	q, ok := s.buckets[id]
	if !ok {
		return e
	}

	var evt *Kevent
	if len(q) > 0 {
		evt, s.buckets[id] = q[0], q[1:]
	}

	if evt == nil {
		return e
	}

	callstack := e.Kparams.MustGetSlice(kparams.Callstack)
	evt.AppendParam(kparams.Callstack, kparams.Slice, callstack)

	return evt
}

// Stop shutdowns the stack walk decorator flusher.
func (s *StackwalkDecorator) Stop() {
	s.quit <- struct{}{}
}

// RemoveBucket removes the bucket and all enqueued events.
func (s *StackwalkDecorator) RemoveBucket(id uint64) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.buckets, id)
}

func (s *StackwalkDecorator) doFlush() {
	for {
		select {
		case <-s.flusher.C:
			errs := s.flush()
			if len(errs) > 0 {
				log.Warnf("callstack: unable to flush queued events: %v", multierror.Wrap(errs...))
			}
		case <-s.quit:
			return
		}
	}
}

// flush pushes events to the event queue if they have
// been living in the deque more than the maximum allowed
// flush period.
func (s *StackwalkDecorator) flush() []error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if len(s.buckets) == 0 {
		return nil
	}

	errs := make([]error, 0)

	for id, q := range s.buckets {
		for i, evt := range q {
			if time.Since(evt.Timestamp) < maxDequeFlushPeriod {
				continue
			}
			callstackFlushes.Add(1)
			err := s.q.push(evt)
			if err != nil {
				errs = append(errs, err)
			}
			s.buckets[id] = append(q[:i], q[i+1:]...)
		}
	}

	return errs
}
