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
var maxReservedStackWait = time.Second * 2

// reservedStack is a callstack parked under the timestamp of the event
// it belongs to.
type reservedStack struct {
	pid, tid uint32
	addrs    va.Callstack
}

// CallstackLinker splices callstack return addresses into the
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
type CallstackLinker struct {
	// buckets holds events waiting for their stack walk and stack walks waiting for their event
	buckets map[uint64]*event.Event
	mu      sync.Mutex

	flusher *time.Ticker

	// clock is the monotonic clock
	clock uint64

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

// Put registers an event that is eligible for stack enrichment. If its
// stack walk has already arrived or the reservation exists, the callstack
// is attached and the event is returned for publishing. Otherwise, the event
// is parked until splice receives the stack walk.
func (l *CallstackLinker) Put(e *event.Event) *event.Event {
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
		l.procs[e.Params.MustGetPid()] = e.Clone()
	}

	// CreateFile claims the callstack reserved by its stack walk
	if stack, reserved := l.reservations[ts]; reserved {
		delete(l.reservations, ts)
		e.AppendParam(params.Callstack, params.Slice, stack.addrs)
		return e
	}

	// park the event indexed by timestamp
	l.buckets[ts] = e.Clone()

	return nil
}

// Link receives the stack walk data and attempts to connect the
// originating event to its callstack. If the connection succeeds
// the originating events are then decorated with callstack return
// addresses and dispatchers to consumers/listeners. If the originating
// event hasn't arrived yet, the stack walk is parked.
func (l *CallstackLinker) Link(ts uint64, pid, tid uint32, addrs va.Callstack) {
	l.mu.Lock()

	l.advance(ts)
	var evts []*event.Event

	evt, ok := l.buckets[ts]
	if !ok {
		// park the stack walk, the event hasn't reached put yet
		l.stacks[ts] = reservedStack{pid: pid, tid: tid, addrs: addrs}
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
			ev.AppendParam(params.Callstack, params.Slice, addrs.Clone())
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
func (l *CallstackLinker) reserve(ts uint64, pid, tid uint32, addrs va.Callstack) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.advance(ts)
	l.reservations[ts] = reservedStack{pid: pid, tid: tid, addrs: addrs}
}

func (l *CallstackLinker) releaseReservation(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if reservation, exists := l.reservations[id]; exists {
		reservation.addrs.ReleasePool()
		delete(l.reservations, id)
	}
}

// Close stops the eviction loop. It is safe to call it more than once.
func (l *CallstackLinker) close() {
	l.closeOnce.Do(func() { close(l.done) })
}

// flushLoop periodically evicts expired entries until the linker is closed.
func (l *CallstackLinker) flushLoop() {
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
func (l *CallstackLinker) advance(ts uint64) {
	if ts > l.clock {
		l.clock = ts
	}
}

// expired reports whether the entry stamped with ts is older than ttl
// relative to the linker clock. The timestamps are in nanoseconds. The
// caller must hold the mutex.
func (l *CallstackLinker) expired(ts uint64, ttl time.Duration) bool {
	return l.clock > ts && l.clock-ts >= uint64(ttl)
}

// evictExpired removes entries that have been pending longer than the
// maximum stack wait period. Events are published without the callstack,
// while orphaned stack walks are discarded.
func (l *CallstackLinker) evictExpired() {
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
func (l *CallstackLinker) expireReservations() {
	for ts, s := range l.reservations {
		if l.expired(ts, maxReservedStackWait) {
			s.addrs.ReleasePool()
			delete(l.reservations, ts)
		}
	}
	// stack walks are parked for any event, including ones that never
	// reach Put, so they use the shorter wait
	for ts, s := range l.stacks {
		if l.expired(ts, maxStackWait) {
			s.addrs.ReleasePool()
			delete(l.stacks, ts)
		}
	}
}

// removeSurrogate stops tracking the CreateProcess event with surrogate
// parent. The caller must hold the mutex.
func (s *CallstackLinker) removeSurrogate(e *event.Event) {
	if e.IsSurrogateProcess() {
		delete(s.procs, e.Params.MustGetPid())
	}
}

// NewCallstackLinker creates a new callstack linker which receives
// the probe. Events that outlive the maximum stack wait period are
// evicted to the handlers/consumers without the callstack.
func NewCallstackLinker(probe *Probe) *CallstackLinker {
	l := &CallstackLinker{
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
