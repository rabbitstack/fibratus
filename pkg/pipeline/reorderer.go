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

// Reorderer restores a total timestamp order across sessions.
//
// Every session delivers its own events in (roughly) increasing time, so the
// smallest pending timestamp is safe to release once every session has shown
// that it has moved past it. For each session the reorderer tracks the highest
// timestamp seen (its frontier). The watermark is the minimum frontier minus
// Slack, and everything at or below it is released in order.
//
// A session that goes quiet would freeze the watermark, so a session that has
// delivered nothing for IdleTimeout is treated as caught up to "now".
//
// Slack absorbs skew inside a session (ETW delivers per-CPU buffers on a
// timer). An event that still arrives behind the released stream is emitted
// immediately and counted in Late: use that counter to tune Slack.
//
// Timestamps and the clock must be in the same domain (system time derived
// from QPC, for example). The reorderer is not safe for concurrent use.
type Reorderer struct {
	h          eventHeap
	slack      int64
	idle       int64
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

// NewReorderer creates a reorderer for the given number of sessions. now is
// the current time in the event time domain. Sessions count as active from it.
func NewReorderer(sessions int, slack, idle int64, maxPending int, now int64) *Reorderer {
	r := &Reorderer{
		slack:       slack,
		idle:        idle,
		maxPending:  maxPending,
		maxTS:       make([]int64, sessions),
		seen:        make([]bool, sessions),
		lastSeen:    make([]int64, sessions),
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

// Add inserts an event that arrived from the given session at time now.
func (r *Reorderer) Add(session int, ev *event.Event, now int64) {
	key := ev.Timestamp.UnixNano()
	r.n++
	r.h.push(entry{key: key, n: r.n, ev: ev})
	if !r.seen[session] || key > r.maxTS[session] {
		r.maxTS[session] = key
		r.seen[session] = true
	}
	r.lastSeen[session] = now
}

// Watermark returns the timestamp up to which events can be released. ok is
// false while some session has neither delivered anything nor been idle long
// enough to be ignored.
func (r *Reorderer) Watermark(now int64) (wm int64, ok bool) {
	wm = math.MaxInt64
	for s := range r.maxTS {
		f, known := r.maxTS[s], r.seen[s]
		if now-r.lastSeen[s] >= r.idle { // quiet session: treat as caught up
			if !known || now > f {
				f, known = now, true
			}
		}
		if !known {
			return 0, false
		}
		if f < wm {
			wm = f
		}
	}
	return wm - r.slack, true
}

// Next releases the oldest pending event if it is at or below the watermark.
// If the heap is full it releases the oldest event regardless (bounded memory
// beats strict order) and counts it as forced.
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
