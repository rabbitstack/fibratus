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
	"expvar"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/periodical"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// maxStackWait specifies the maximum period an entry (an event
// waiting for its stack walk, or a stack walk waiting for its
// event) can reside in the pending map before it is evicted.
var maxStackWait = time.Second * 2

// evictInterval specifies the interval at which the pending
// map is scanned for expired entries.
var evictInterval = time.Millisecond * 500

// stackwalkFlushes computes overall flushes for unmatched stackwalk events
var stackwalkFlushes = expvar.NewInt("stackwalk.flushes")

// stackwalkFlushesProcs computes overall flushes for unmatched stackwalk events per process
var stackwalkFlushesProcs = expvar.NewMap("stackwalk.flushes.procs")

// stackwalkFlushesEvents computes overall flushes for unmatched stackwalks per event type
var stackwalkFlushesEvents = expvar.NewMap("stackwalk.flushes.events")

// stackwalkUnordered counts the unordered stackwalk matches
var stackwalkUnorderedMatches = expvar.NewInt("stackwalk.unordered.matches")

// stackwalkUnorderedEnqueued counts enqueued unordered stackwalk matches
var stackwalkUnorderedEnqueued = expvar.NewInt("stackwalk.unordered.enqueued")

// stackwalkSurrogateProcessHits counts the number of hits where the callstack is attributed from
// the surrogate thread creation event
var stackwalkSurrogateProcessHits = expvar.NewInt("stackwalk.surrogate.process.hits")

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
type CallstackLinker struct {
	// buckets holds events waiting for their stack walk and stack walks waiting for their event
	buckets map[uint64]*event.Event

	periodical *periodical.Periodical

	procs map[uint32]*event.Event // stores CreateProcess events with surrogate parent

	// stacks holds the stack walks that arrived for reserved events and are waiting to be claimed
	stacks map[uint64]reservedStack

	probe *Probe
}

// Put registers an event that is eligible for stack enrichment. If its
// stack walk has already arrived or the reservation exists, the callstack
// is attached and the event is returned for publishing. Otherwise, the event
// is parked until splice receives the stack walk.
func (l *CallstackLinker) Put(e *event.Event) *event.Event {
	ts := e.RawTimestamp()

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
	evt, ok := l.buckets[ts]
	if !ok {
		// park the stack walk, the event hasn't reached Put yet
		l.stacks[ts] = reservedStack{pid: pid, tid: tid, addrs: addrs}
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
			l.probe.dispatchEvent(ev)
		}
	}

	l.probe.dispatchEvent(evt)
}

// evictExpired removes entries that have been pending longer than the
// maximum stack wait period. Events are published without the callstack,
// while orphaned stack walks are discarded.
func (l *CallstackLinker) evictExpired() {
	for ts, s := range l.stacks {
		if !l.expired(filetime.Nanoseconds(ts)) {
			continue
		}
		s.addrs.ReleasePool()
		delete(l.stacks, ts)
	}
	for ts, evt := range l.buckets {
		if !l.expired(filetime.Nanoseconds(ts)) {
			continue
		}
		delete(l.buckets, ts)
		l.removeSurrogate(evt)
		l.probe.dispatchEvent(evt)

		stackwalkFlushes.Add(1)
		if evt.PS != nil {
			stackwalkFlushesProcs.Add(evt.PS.Name, 1)
		}
		stackwalkFlushesEvents.Add(evt.Name(), 1)
	}
}

// removeSurrogate stops tracking the CreateProcess event with surrogate
// parent. The caller must hold the mutex.
func (s *CallstackLinker) removeSurrogate(e *event.Event) {
	if e.IsSurrogateProcess() {
		delete(s.procs, e.Params.MustGetPid())
	}
}

// doPeriodic advances the event-time clock and evicts the expired entries once per
// eviction interval.
func (l *CallstackLinker) doPeriodic(ts int64) { l.periodical.Do(ts, l.evictExpired) }

// expired reports whether an entry parked at the given clock reading has
// waited longer than maxStackWait.
func (l *CallstackLinker) expired(at int64) bool {
	return l.periodical.Clock()-at >= int64(maxStackWait)
}

// NewCallstackLinker creates a new callstack linker which receives
// the probe. Events that outlive the maximum stack wait period are
// evicted to the handlers/consumers without the callstack.
func NewCallstackLinker(probe *Probe) *CallstackLinker {
	l := &CallstackLinker{
		probe:      probe,
		periodical: periodical.New(evictInterval),
		buckets:    make(map[uint64]*event.Event),
		procs:      make(map[uint32]*event.Event),
		stacks:     make(map[uint64]reservedStack),
	}
	return l
}
