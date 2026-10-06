//go:build windows

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

import (
	"os"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// maxStackWait specifies the maximum period an entry (an event
// waiting for its stack walk, or a stack walk waiting for its
// event) can reside in the pending map before it is evicted.
var maxStackWait = time.Millisecond * 500

// evictInterval specifies the interval at which the pending
// map is scanned for expired entries.
var evictInterval = time.Millisecond * 250

// maxReservedStackWait specifies the maximum period a reservation, or a
// callstack waiting to be claimed, can reside in the linker. It must cover
// the time the caller keeps the event aside, e.g. the span between the
// CreateFile event and the FileOpEnd event that completes the same IRP.
var maxReservedStackWait = time.Second * 10

// reservedStack is a callstack parked under the timestamp of the event
// it belongs to.
type reservedStack struct {
	pid, tid uint32
	addrs    []va.Address
}

// callstackLinker splices callstack return addresses into the
// events that triggered them. Events eligible for stack enrichment
// are held in a pending map indexed by stack id until the respective
// stack walk event arrives. Since the two can arrive in either order,
// an early stack walk is parked in the same map until its event shows
// up. Once paired, the event is decorated with the return addresses
// which are later subject to symbolization.
//
// Some events, such as CreateFile, are kept aside by the caller until a
// later event completes them (FileOpEnd for the same IRP), so they are
// never held here. For these, the caller reserves the stack id up front
// with Reserve. When the stack walk arrives, the callstack is stored in
// the linker, and the caller picks it up with Claim once the event is
// released, without the event ever residing in the linker.
type callstackLinker struct {
	// buckets holds events waiting for their stack walk,
	// and stack walks waiting for their event
	buckets map[uint64]*event.Event
	mu      sync.Mutex

	flusher *time.Ticker
	clock   uint64

	procs map[uint32]*event.Event // stores CreateProcess events with surrogate parent

	done      chan struct{}
	closeOnce sync.Once

	// stacks holds the stack walks that arrived for reserved events and
	// are waiting to be claimed
	stacks map[uint64]reservedStack

	// reservations holds the stack ids of the events the caller keeps aside and
	// will claim the callstack for later
	reservations map[uint64]reservedStack

	probe *Probe
}

// newCallstackLinker creates a new callstack linker which receives
// the downstream event queue. Events that outlive the maximum stack
// wait period are evicted to the queue without the callstack.
func newCallstackLinker(probe *Probe) *callstackLinker {
	l := &callstackLinker{
		probe:        probe,
		buckets:      make(map[uint64]*event.Event),
		procs:        make(map[uint32]*event.Event),
		reservations: make(map[uint64]reservedStack),
		stacks:       make(map[uint64]reservedStack),
		flusher:      time.NewTicker(evictInterval),
		done:         make(chan struct{}),
	}

	go l.flushLoop()

	return l
}

// Put registers an event that is eligible for stack enrichment. If its
// stack walk has already arrived the callstack is attached and the event
// is returned for publishing. Otherwise, the event is parked until splice
// receives the stack walk.
func (l *callstackLinker) put(e *event.Event) *event.Event {
	ts := e.RawTimestamp()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.advance(ts)

	// the stack walk arrived ahead of the event
	if stack, ok := l.stacks[ts]; ok {
		//stackwalkUnorderedMatches.Add(1)
		delete(l.stacks, ts)
		e.AppendParam(params.Callstack, params.Slice, stack.addrs)
		return e
	}

	// the process is created on behalf of brokered
	// process and the callstack return addresses
	// need to be obtained from the surrogate process.
	// Only track it while it is parked, otherwise the
	// entry would never be cleaned up
	if e.IsSurrogateProcess() {
		l.procs[e.Params.MustGetPid()] = e
	}

	// CreateFile claims the callstack reserved by its stack walk
	if stack, reserved := l.reservations[ts]; reserved {
		delete(l.reservations, ts)
		e.AppendParam(params.Callstack, params.Slice, stack.addrs)
		return e
	}

	// park the event indexed by timestamp
	l.buckets[ts] = e

	return nil
}

// splice receives the stack walk data and attempts to connect the
// originating event to its callstack. If the connection succeeds
// the originating events are then decorated with callstack return
// addresses and dispatchers to consumers/listeners. If the originating
// event hasn't arrived yet, the stack walk is parked.
func (l *callstackLinker) splice(ts uint64, pid, tid uint32, addrs []va.Address) {
	l.mu.Lock()

	l.advance(ts)
	var evts []*event.Event

	evt, ok := l.buckets[ts]
	if !ok {
		// park the stack walk, the event hasn't reached put yet
		if pid != uint32(os.Getpid()) {
			l.stacks[ts] = reservedStack{pid: pid, tid: tid, addrs: addrs}
		}
		l.mu.Unlock()
		return
	}
	delete(l.buckets, ts)
	l.removeSurrogate(evt)

	evt.AppendParam(params.Callstack, params.Slice, addrs)

	// Obtain the callstack from the CreateThread event generated by the
	// surrogate/brokered process, such as Secondary Logon. If the remote
	// process id is present in the procs map, the stack is attached to the
	// parked CreateProcess event, which is published together with the
	// CreateRemoteThread event. The CreateProcess event goes first since
	// it happened first.
	if evt.IsCreateRemoteThread() {
		pid := evt.Params.MustGetPid()
		if ev, ok := l.procs[pid]; ok {
			ev.AppendParam(params.Callstack, params.Slice, addrs)
			delete(l.procs, pid)
			delete(l.buckets, ev.RawTimestamp())
			evts = append(evts, ev)
		}
	}
	l.mu.Unlock()

	// publish without holding the mutex
	l.probe.dispatchEvents(evts...)
}

// reserve announces an event that the caller keeps aside and releases on
// its own, such as CreateFile, which waits for FileOpEnd. The event is not
// held in the linker. Instead, when its stack walk arrives, the callstack
// is stored until the caller picks it up with Claim. Reserve must be called
// before the event is set aside. If the stack walk has already arrived and
// was parked, it is moved to the claimable store right away.
func (l *callstackLinker) reserve(ts uint64, pid, tid uint32, addrs []va.Address) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.advance(ts)
	l.reservations[ts] = reservedStack{pid: pid, tid: tid, addrs: addrs}
}

func (l *callstackLinker) releaseReservation(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.reservations, id)
}

// Close stops the eviction loop. It is safe to call it more than once.
func (l *callstackLinker) close() {
	l.closeOnce.Do(func() { close(l.done) })
}

// flushLoop periodically evicts expired entries until the linker is closed.
func (l *callstackLinker) flushLoop() {
	defer l.flusher.Stop()
	for {
		select {
		case <-l.flusher.C:
			l.evictExpired()
		case <-l.done:
			return
		}
	}
}

// advance moves the linker clock forward to the newest timestamp seen.
// The mark never moves backwards, so a single far-future timestamp from
// a different clock base would expire everything. The caller must hold
// the mutex before advancing the clock.
func (l *callstackLinker) advance(ts uint64) {
	if ts > l.clock {
		l.clock = ts
	}
}

// expired reports whether the entry stamped with ts is older than ttl
// relative to the linker clock. The timestamps are in nanoseconds. The
// caller must hold the mutex.
func (l *callstackLinker) expired(ts uint64, ttl time.Duration) bool {
	return l.clock > ts && l.clock-ts >= uint64(ttl)
}

// evictExpired removes entries that have been pending longer than the
// maximum stack wait period. Events are published without the callstack,
// while orphaned stack walks are discarded.
func (l *callstackLinker) evictExpired() {
	l.mu.Lock()

	l.expireReservations()

	var expired []*event.Event

	for ts, evt := range l.buckets {
		if !l.expired(ts, maxStackWait) {
			continue
		}
		expired = append(expired, evt)
		delete(l.buckets, ts)
		l.removeSurrogate(evt)
	}

	l.mu.Unlock()

	// publish without holding the mutex
	l.probe.dispatchEvents(expired...)
}

// expireReservations drops the reservations and the parked stack walks
// that outlived the maximum reserved stack wait period. The caller must
// hold the mutex.
func (l *callstackLinker) expireReservations() {
	for ts := range l.reservations {
		if l.expired(ts, maxReservedStackWait) {
			delete(l.reservations, ts)
		}
	}
	// stack walks are parked for any event, including ones that never
	// reach Put, so they use the shorter wait
	for ts := range l.stacks {
		if l.expired(ts, maxStackWait) {
			delete(l.stacks, ts)
		}
	}
}

// removeSurrogate stops tracking the CreateProcess event with surrogate
// parent. The caller must hold the mutex.
func (s *callstackLinker) removeSurrogate(e *event.Event) {
	if e.IsSurrogateProcess() {
		delete(s.procs, e.Params.MustGetPid())
	}
}

// type StackwalkDecorator struct {
// 	buckets map[uint64]*Event
// 	q       *Queue
// 	mux     sync.Mutex

// 	flusher *time.Ticker
// 	quit    chan struct{}

// 	procs map[uint32]*Event // stores CreateProcess events with surrogate parent
// }

// // NewStackwalkDecorator creates a new callstack return
// // addresses decorator which receives the event queue
// // for long-standing event flushing.
// func NewStackwalkDecorator(q *Queue) *StackwalkDecorator {
// 	s := &StackwalkDecorator{
// 		q:       q,
// 		buckets: make(map[uint64]*Event),
// 		procs:   make(map[uint32]*Event),
// 		flusher: time.NewTicker(flusherInterval),
// 		quit:    make(chan struct{}, 1),
// 	}

// 	go s.doFlush()

// 	return s
// }

// // Push pushes a new event to the queue.
// func (s *StackwalkDecorator) Push(e *Event) {
// 	s.mux.Lock()
// 	defer s.mux.Unlock()

// 	// the process is created on behalf of brokered
// 	// process and the callstack return addresses
// 	// need to be obtained from the surrogate process
// 	if e.IsSurrogateProcess() {
// 		s.procs[e.Params.MustGetPid()] = e
// 	}

// 	id := e.RawTimestamp()

// 	// check if we have the previous stack walk event
// 	if evt, ok := s.buckets[id]; ok && evt.IsStackWalk() {
// 		stackwalkUnorderedMatches.Add(1)
// 		callstack := evt.Params.MustGetSlice(params.Callstack)
// 		e.AppendParam(params.Callstack, params.Slice, callstack)
// 		delete(s.buckets, id)
// 		_ = s.q.push(e)
// 	} else {
// 		// store the event to the bucket indexed by stack id
// 		s.buckets[id] = e
// 	}
// }

// // Pop receives the stack walk event and pops the oldest
// // originating event with the same pid,tid tuple formerly
// // coined as stack identifier. The originating event is then
// // decorated with callstack return addresses.
// func (s *StackwalkDecorator) Pop(e *Event) *Event {
// 	s.mux.Lock()
// 	defer s.mux.Unlock()

// 	id := e.Params.MustGetUint64(params.CallstackTimestamp)
// 	evt, ok := s.buckets[id]
// 	if !ok {
// 		// enqueue if the stack walk arrived out of order
// 		if e.Params.MustGetPid() != currentPid {
// 			s.buckets[id] = e
// 			stackwalkUnorderedEnqueued.Add(1)
// 		}
// 		return e
// 	}
// 	delete(s.buckets, id)

// 	if evt.IsSurrogateProcess() && s.procs[evt.Params.MustGetPid()] != nil {
// 		delete(s.procs, evt.Params.MustGetPid())
// 	}

// 	callstack := e.Params.MustGetSlice(params.Callstack)
// 	evt.AppendParam(params.Callstack, params.Slice, callstack)

// 	// obtain the callstack from the CreateThread event
// 	// generated by the surrogate/brokered process, such as
// 	// Secondary Logon.
// 	// If the remote process id is present in the procs map
// 	// the stack is attached to the cached event and then
// 	// pushed to the queue immediately
// 	if evt.IsCreateRemoteThread() {
// 		pid := evt.Params.MustGetPid()
// 		ev, ok := s.procs[pid]
// 		if ok {
// 			ev.AppendParam(params.Callstack, params.Slice, callstack)
// 			_ = s.q.push(ev)
// 			delete(s.procs, pid)
// 			delete(s.buckets, ev.RawTimestamp())
// 			stackwalkSurrogateProcessHits.Add(1)
// 		}
// 	}

// 	return evt
// }

// // Stop shutdowns the stack walk decorator flusher.
// func (s *StackwalkDecorator) Stop() {
// 	s.quit <- struct{}{}
// }

// func (s *StackwalkDecorator) doFlush() {
// 	for {
// 		select {
// 		case <-s.flusher.C:
// 			errs := s.flush()
// 			if len(errs) > 0 {
// 				log.Warnf("callstack: unable to flush queued events: %v", multierror.Wrap(errs...))
// 			}
// 		case <-s.quit:
// 			return
// 		}
// 	}
// }

// // flush pushes events to the event queue if they have
// // been living in the queue more than the maximum allowed
// // TTL period.
// func (s *StackwalkDecorator) flush() []error {
// 	s.mux.Lock()

// 	if len(s.buckets) == 0 {
// 		s.mux.Unlock()
// 		return nil
// 	}

// 	expired := make([]*Event, 0)

// 	for id, evt := range s.buckets {
// 		if time.Since(evt.Timestamp) < maxQueueTTLPeriod {
// 			continue
// 		}
// 		expired = append(expired, evt)
// 		delete(s.buckets, id)
// 	}

// 	s.mux.Unlock()
// 	errs := make([]error, 0)

// 	// push expired events without holding the mutex.
// 	// This allows incoming Push()/Pop() calls to proceed
// 	// while the channel send may block briefly
// 	for _, evt := range expired {
// 		if evt.IsStackWalk() {
// 			continue
// 		}
// 		stackwalkFlushes.Add(1)

// 		err := s.q.push(evt)
// 		if err != nil {
// 			errs = append(errs, err)
// 		}
// 		if evt.PS != nil {
// 			stackwalkFlushesProcs.Add(evt.PS.Name, 1)
// 		}
// 		stackwalkFlushesEvents.Add(evt.Name(), 1)
// 	}

// 	return errs
// }
