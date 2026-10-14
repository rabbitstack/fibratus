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

package pipeline

import (
	"math"
	"sync/atomic"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// entry is one pending event in the reorder heap. n is the arrival counter,
// which keeps the order stable for equal timestamps.
type entry struct {
	key int64
	n   uint64
	ev  *event.Event
}

// eventHeap is a hand-rolled min-heap: container/heap would box every entry
// into an interface value.
type eventHeap []entry

func (h eventHeap) less(i, j int) bool {
	if h[i].key != h[j].key {
		return h[i].key < h[j].key
	}
	return h[i].n < h[j].n
}

func (h *eventHeap) push(e entry) {
	*h = append(*h, e)
	s := *h
	i := len(s) - 1
	for i > 0 {
		p := (i - 1) / 2
		if !s.less(i, p) {
			break
		}
		s[i], s[p] = s[p], s[i]
		i = p
	}
}

func (h *eventHeap) pop() entry {
	s := *h
	top := s[0]
	last := len(s) - 1
	s[0] = s[last]
	s[last] = entry{} // don't pin the event
	s = s[:last]
	*h = s
	i := 0
	for {
		l := 2*i + 1
		if l >= len(s) {
			break
		}
		m := l
		if r := l + 1; r < len(s) && s.less(r, l) {
			m = r
		}
		if !s.less(m, i) {
			break
		}
		s[i], s[m] = s[m], s[i]
		i = m
	}
	return top
}

// ReorderStats are the reorderer's counters.
type ReorderStats struct {
	Emitted uint64 // events released downstream
	Late    uint64 // events that arrived after a later one was already released
	Forced  uint64 // events released early because the heap hit MaxPending
	Pending int    // events currently held back
}

// Reorderer restores a total timestamp order across event sources.
//
// Every source delivers its own events in (roughly) increasing time, so the
// smallest pending timestamp is safe to release once every source has shown
// that it has moved past it. For each source the reorderer tracks the highest
// timestamp seen (its frontier). The watermark is the minimum frontier minus
// Slack, and everything at or below it is released in order.
//
// A source that goes quiet would freeze the watermark, so a source that has
// delivered nothing for IdleTimeout is treated as caught up to "now".
//
// Slack absorbs skew inside a source. An event that still arrives behind the
// released stream is emitted immediately and counted in Late.
//
// Timestamps and the clock must be in the same domain (system time derived
// from QPC, for example). The reorderer is not safe for concurrent use.
type Reorderer struct {
	h          eventHeap
	slack      int64
	idle       int64
	maxHold    int64
	maxPending int

	maxTS    []int64
	seen     []bool
	lastSeen []int64

	n           uint64
	lastEmitted int64

	emitted atomic.Uint64
	late    atomic.Uint64
	forced  atomic.Uint64
}

// NewReorderer creates a reorderer for the given number of producers. now is
// the current time in the event time domain. Producers count as active from it.
func NewReorderer(producers int, slack, idle, maxHold int64, maxPending int, now int64) *Reorderer {
	r := &Reorderer{
		slack:       slack,
		idle:        idle,
		maxHold:     maxHold,
		maxPending:  maxPending,
		maxTS:       make([]int64, producers),
		seen:        make([]bool, producers),
		lastSeen:    make([]int64, producers),
		lastEmitted: math.MinInt64,
	}
	for i := range r.lastSeen {
		r.lastSeen[i] = now
	}
	r.h = make(eventHeap, 0, min(maxPending, 1<<12))
	return r
}

// Len returns the number of pending events.
func (r *Reorderer) Len() int { return len(r.h) }

// Add inserts an event that arrived from the given producer at time now.
func (r *Reorderer) Add(producer int, ev *event.Event, now int64) {
	key := ev.Timestamp.UnixNano()
	r.n++
	r.h.push(entry{key: key, n: r.n, ev: ev})
	if !r.seen[producer] || key > r.maxTS[producer] {
		r.maxTS[producer] = key
		r.seen[producer] = true
	}
	r.lastSeen[producer] = now
}

// Watermark returns the timestamp up to which events can be released. ok is
// false while some producer has neither delivered anything nor been idle long
// enough to be ignored.
func (r *Reorderer) Watermark(now int64) (wm int64, ok bool) {
	wm = math.MaxInt64
	for s := range r.maxTS {
		f, known := r.maxTS[s], r.seen[s]
		if now-r.lastSeen[s] >= r.idle { // quiet producer: treat as caught up
			if !known || now > f {
				f, known = now, true
			}
		}
		if !known {
			// a producer has never delivered: don't freeze release,
			// fall back to the hold floor only
			return now - r.maxHold, r.maxHold > 0
		}
		if f < wm {
			wm = f
		}
	}
	wm -= r.slack
	if r.maxHold > 0 {
		if floor := now - r.maxHold; wm < floor {
			wm = floor
		}
	}
	return wm, true
}

// Next releases the oldest pending event if it is at or below the watermark.
// If the heap is full it releases the oldest event regardless and counts it
// as forced.
func (r *Reorderer) Next(wm int64, ok bool) (*event.Event, bool) {
	if len(r.h) == 0 {
		return nil, false
	}
	forced := false
	if !ok || r.h[0].key > wm {
		if len(r.h) < r.maxPending {
			return nil, false
		}
		forced = true
	}
	e := r.h.pop()
	if forced {
		r.forced.Add(1)
	}
	if e.key < r.lastEmitted {
		r.late.Add(1)
	} else {
		r.lastEmitted = e.key
	}
	r.emitted.Add(1)
	return e.ev, true
}

// Stats returns a snapshot of the counters. Safe from any goroutine except for
// Pending, which is only accurate when read by the owner.
func (r *Reorderer) Stats() ReorderStats {
	return ReorderStats{
		Emitted: r.emitted.Load(),
		Late:    r.late.Load(),
		Forced:  r.forced.Load(),
		Pending: len(r.h),
	}
}

// passthrough is a diagnostic stand-in for Reorderer. It is a plain FIFO:
// no heap, no watermark, no slack. Events are released in arrival order on
// the next emit pass, so pending is at most one ingest batch per producer.
type passthrough struct {
	q       []*event.Event
	head    int
	emitted atomic.Uint64
}

func newPassthrough() *passthrough { return &passthrough{} }

func (r *passthrough) Len() int { return len(r.q) - r.head }

func (r *passthrough) Add(_ int, ev *event.Event, _ int64) {
	r.q = append(r.q, ev)
}

// Watermark is ignored by Next, but keep the signature identical.
func (r *passthrough) Watermark(int64) (int64, bool) { return 0, true }

func (r *passthrough) Next(int64, bool) (*event.Event, bool) {
	if r.head == len(r.q) {
		r.q, r.head = r.q[:0], 0 // reuse the backing array
		return nil, false
	}
	ev := r.q[r.head]
	r.q[r.head] = nil // don't pin the event
	r.head++
	r.emitted.Add(1)
	return ev, true
}

func (r *passthrough) Stats() ReorderStats {
	return ReorderStats{Emitted: r.emitted.Load(), Pending: r.Len()}
}
