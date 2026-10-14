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
	"fmt"
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

// LateHook is invoked from Add when an event arrives behind the released
// stream. behind is how far (ns) its timestamp is below the last emitted
// timestamp, and delay is the delivery delay (ns), i.e. now - event timestamp.
// The p99.9 of delay per session is the value to use for lag.
type LateHook func(producerID int, behind, delay int64)

// Reorderer restores a total timestamp order across sessions.
//
// Every session delivers its own events in (roughly) increasing time, so the
// smallest pending timestamp is safe to release once every session has shown
// that it has moved past it. For each session the reorderer tracks the highest
// timestamp seen (its frontier). The watermark is the minimum frontier minus
// Slack, and everything at or below it is released in order.
//
// A quiet session would freeze the watermark, so no frontier is allowed to lag
// behind now-lag. lag is the longest an event can sit in an ETW buffer before
// it is delivered: the largest FlushTimer among the sessions plus scheduling
// jitter. A session that has delivered nothing is therefore assumed to hold,
// at most, events newer than now-lag, instead of being declared caught up to
// "now": anything generated in the last FlushTimer interval may still be
// sitting in a buffer that has not been flushed yet.
//
// Slack absorbs skew inside a session (ETW delivers per-CPU buffers on a
// timer). An event that still arrives behind the released stream is emitted
// immediately and counted in Late: use that counter, and the LateHook, to tune
// lag and Slack.
//
// Worst-case emission latency is about lag + slack.
//
// maxPending must be at least the peak event rate multiplied by (lag + slack),
// otherwise the forced path pops events before the watermark and causes the
// same inversions.
//
// Timestamps and the clock must be in the same domain (system time derived
// from QPC, for example). The reorderer is not safe for concurrent use.
type Reorderer struct {
	h          eventHeap
	slack      int64
	lag        int64
	maxHold    int64
	maxPending int

	// maxTS is the maximum timestamp observed for each producer.
	maxTS []int64
	// initialized distinguishes an unseen producer from a timestamp of zero.
	initialized []bool

	n           uint64
	lastEmitted int64

	onLate LateHook

	emitted atomic.Uint64
	late    atomic.Uint64
	forced  atomic.Uint64
	pending atomic.Int64
}

// NewReorderer creates a best-effort timestamp reorderer. for the given number of producers. slack and
// lag are expressed in nanoseconds.
func NewReorderer(producers int, slack, lag int64, maxPending int) *Reorderer {
	switch {
	case producers <= 0:
		panic("pipeline: producers must be positive")
	case slack < 0:
		panic("pipeline: slack must be non-negative")
	case lag < 0:
		panic("pipeline: lag must be non-negative")
	case maxPending <= 0:
		panic("pipeline: maxPending must be positive")
	}

	r := &Reorderer{
		slack:       slack,
		lag:         lag,
		maxPending:  maxPending,
		maxTS:       make([]int64, producers),
		initialized: make([]bool, producers),
		lastEmitted: math.MinInt64,
	}
	r.h = make(eventHeap, 0, min(maxPending, 1<<12))
	return r
}

// saturatingSub returns a-b, saturating at the int64 limits on overflow.
func saturatingSub(a, b int64) int64 {
	if b > 0 && a < math.MinInt64+b {
		return math.MinInt64
	}
	if b < 0 && a > math.MaxInt64+b {
		return math.MaxInt64
	}
	return a - b
}

// SetLateHook registers a callback for events that arrive behind the released
// stream. It is meant for tuning lag and slack. Pass nil to remove it.
func (r *Reorderer) SetLateHook(h LateHook) { r.onLate = h }

// Len returns the number of pending events.
func (r *Reorderer) Len() int { return len(r.h) }

// Add inserts an event that arrived from the given producer at time now.
func (r *Reorderer) Add(producerID int, ev *event.Event, now int64) {
	if producerID < 0 || producerID >= len(r.maxTS) {
		panic(fmt.Sprintf("pipeline: invalid producer index %d", producerID))
	}
	if ev == nil {
		panic("pipeline: cannot reorder a nil event")
	}

	key := ev.Timestamp.UnixNano()

	if r.n == math.MaxUint64 {
		panic("pipeline: arrival sequence exhausted")
	}
	r.n++

	r.h.push(entry{key: key, n: r.n, ev: ev})
	r.pending.Add(1)

	if !r.initialized[producerID] || key > r.maxTS[producerID] {
		r.maxTS[producerID] = key
	}
	r.initialized[producerID] = true

	if key < r.lastEmitted && r.onLate != nil {
		r.onLate(
			producerID,
			saturatingSub(r.lastEmitted, key),
			saturatingSub(now, key),
		)
	}
}

// Watermark returns the timestamp up to which events can be released. Every
// session frontier is clamped to at least now-lag, because anything not yet
// delivered by a session is newer than that. A quiet session therefore cannot
// hold the watermark back past now-lag, and it cannot be declared complete
// beyond it either. ok is always true; it is kept so callers of Next do not
// change.
func (r *Reorderer) Watermark(now int64) (wm int64) {
	floor := saturatingSub(now, r.lag)
	wm = math.MaxInt64

	for i, ts := range r.maxTS {
		frontier := floor
		if r.initialized[i] && ts > frontier {
			frontier = ts
		}
		if frontier < wm {
			wm = frontier
		}
	}

	return saturatingSub(wm, r.slack)
}

// Next releases the oldest pending event if it is at or below the watermark.
// If the heap is full it releases the oldest event regardless (bounded memory
// beats strict order) and counts it as forced.
func (r *Reorderer) Next(wm int64) (*event.Event, bool) {
	if len(r.h) == 0 {
		return nil, false
	}

	forced := r.h[0].key > wm
	if forced && len(r.h) < r.maxPending {
		return nil, false
	}

	e := r.h.pop()
	r.pending.Add(-1)

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
