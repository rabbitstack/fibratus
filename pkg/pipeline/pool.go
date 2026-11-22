package pipeline

import (
	"sync"
	"sync/atomic"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// pool hands out reusable events and bounds how many are alive at once.
//
// Storage is a sync.Pool. Per-P caches keep get/put contention-free between
// the callbacks and the drainer. Events that grew past the recycle limits
// are not kept.
type pool struct {
	p         sync.Pool
	inflight  atomic.Int64
	high      atomic.Int64
	maxFrames int
}

func newPool(maxFrames int) *pool {
	p := &pool{maxFrames: maxFrames}
	p.p.New = func() any { return new(event.Event) }
	return p
}

// get returns a reset event, or nil when MaxEvents are already alive.
func (p *pool) get() *event.Event {
	n := p.inflight.Add(1)
	if n > p.high.Load() {
		p.high.Store(n)
	}
	return p.p.Get().(*event.Event)
}

// put resets the event and returns it to the pool. The event must not be used
// afterwards.
func (p *pool) put(ev *event.Event) {
	ev.Reset()
	if cap(ev.Callstack) > p.maxFrames {
		ev.Callstack = nil
	}
	p.p.Put(ev)
	p.inflight.Add(-1)
}
