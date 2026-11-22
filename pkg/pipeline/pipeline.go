// Package pipeline moves ETW events from the session callbacks to a single
// sink, in timestamp order, without a queue in between.
//
//	ETW session 0 callback ─▶ Emit(0, fill) ─┐
//	                                         ├─▶ Reorderer ─▶ Sink (the Probe)
//	ETW session 1 callback ─▶ Emit(1, fill) ─┘
//
// The pieces are:
//
//   - a pool of reusable events: callbacks fill pooled events in place (pool.go);
//   - the Reorderer: a timestamp min-heap with per-session watermarks that
//     restores a total order across sessions (see reorder.go);
//   - the delivery rule below, which keeps the sink single-threaded.
//
// # Delivery
//
// There is no consumer goroutine. Publish inserts the event into the reorderer
// under a short mutex and then tries to become the drainer. Exactly one
// goroutine drains at a time (a compare-and-swap flag): it pops the events the
// watermark allows, in order, in batches, and calls Sink.Handle outside the
// mutex. A callback that loses the race returns immediately and its event is
// delivered by the current drainer. So:
//
//   - Handle is never called concurrently and sees events in reorderer order,
//     with a happens-before edge between consecutive calls, so the sink needs
//     no locking;
//   - Handle may run on either session's callback goroutine, and on the flusher:
//     do not rely on goroutine or thread affinity;
//   - a slow sink slows the draining callback directly, and the other callbacks
//     as soon as the reorderer holds MaxPending events: Acquire then blocks
//     them (back-pressure) until the drainer makes room.
//
// A flusher goroutine ticks every FlushInterval so that events leave when the
// traffic stops (a quiet session is declared caught up after IdleTimeout).
package pipeline

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// ErrClosed is returned by Acquire/Publish after Close.
var ErrClosed = errors.New("pipeline is closed")

// Sink is the single consumer of the pipeline: the Probe implements it and
// distributes the events to the other handlers.
//
// Handle is called sequentially, in order. The event is recycled as soon as
// Handle returns. A sink that keeps it (sequence rules holding partial
// matches, async consumers, anything handed to another goroutine) must Clone
// it first.
type Sink interface {
	Handle(*event.Event)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(*event.Event)

// Handle calls f(ev).
func (f SinkFunc) Handle(ev *event.Event) { f(ev) }

// Config configures a Pipeline. Start from DefaultConfig.
type Config struct {
	// Sources is the number of event sources. The reorderer keeps one watermark
	// frontier per source.
	Sources int

	// MaxPending bounds the events held by the reorderer, and with them the
	// memory the pipeline can pin. It is both the point where the reorderer
	// releases its oldest event early (out of strict order) instead of waiting
	// for the watermark, and the point where Acquire blocks the callbacks until
	// the drainer has made room.
	MaxPending int

	// BatchSize is the maximum number of events popped per mutex acquisition.
	BatchSize int

	// Slack is the skew the reorderer tolerates before declaring an event
	// late. IdleTimeout is how long a silent session may hold the watermark.
	Slack time.Duration

	// FlushInterval is the flusher's tick: the worst-case extra latency of an
	// event when traffic is too low for Publish to drain it.
	FlushInterval time.Duration

	// Lag is the longest an event can sit in an ETW buffer before it is delivered:
	// the largest FlushTimer among the sessions plus scheduling jitter. A quiet
	// session is assumed to hold events newer than now-Lag, so it holds the
	// watermark back by at most Lag. Worst-case emission latency is about
	// Lag+Slack, and MaxPending must cover peak rate × (Lag+Slack).
	Lag time.Duration

	// OnLate, if set, is called (under the pipeline lock: keep it fast) for
	// events that arrive behind the released stream. behind and delay are in
	// nanoseconds; the p99.9 of delay per session is the value to give Lag.
	OnLate LateHook

	// RecycleMaxFrames stop one outlier from pinning memory forever. A recycled
	// event whose call stack capacity exceeds RecycleMaxFrames gives that storage
	// back instead of keeping it.
	RecycleMaxFrames int

	// Sink receives the events. Must be set.
	Sink Sink

	// OnPanic is called when Sink.Handle panics. The event is dropped and the
	// pipeline keeps running (a panic must not leave the drain flag held).
	OnPanic func(ev *event.Event, v any)

	// Clock returns the current time in the same domain as Event.Timestamp
	// (UnixNano). Defaults to time.Now.
	Clock func() int64
}

// DefaultConfig returns a configuration to start tuning from.
func DefaultConfig(sources int) Config {
	return Config{
		Sources:          sources,
		MaxPending:       1 << 16,
		BatchSize:        128,
		Slack:            100 * time.Millisecond,
		Lag:              2650 * time.Millisecond,
		FlushInterval:    5 * time.Millisecond,
		RecycleMaxFrames: 80,
	}
}

func (c *Config) validate() error {
	switch {
	case c.Sink == nil:
		return errors.New("pipeline: Sink is required")
	case c.Sources < 1:
		return errors.New("pipeline: Sources must be >= 1")
	case c.MaxPending < 1:
		return errors.New("pipeline: MaxPending must be >= 1")
	case c.BatchSize < 1:
		return errors.New("pipeline: BatchSize must be >= 1")
	case c.Slack < 0:
		return errors.New("pipeline: Slack must be >= 0")
	case c.FlushInterval <= 0:
		return errors.New("pipeline: FlushInterval must be > 0")
	case c.RecycleMaxFrames < 0:
		return errors.New("pipeline: Recycle limits must be >= 0")
	}
	return nil
}

// Pipeline owns the pool, the reorderer and the flusher.
type Pipeline struct {
	cfg     Config
	clock   func() int64
	sink    Sink
	pool    *pool
	sources []sourceStats

	mu          sync.Mutex // guards ro and pendingHigh
	cond        *sync.Cond // on mu: signalled by every pop and by Close
	ro          *Reorderer
	pendingHigh int
	pending     atomic.Int64 // len(ro), written under mu, read lock-free by Acquire
	maxPending  int64

	added    atomic.Uint64  // events inserted; lets a drainer detect a missed wake-up
	draining atomic.Bool    // single-flight flag: held by the goroutine delivering
	batch    []*event.Event // drainer-owned scratch

	// beforeRelease, if set, runs after the last empty pop and before the drain
	// flag is released: the window a missed wake-up lives in. Tests only.
	beforeRelease func()
	emitSeq       uint64

	started   atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	quit      chan struct{}
	done      chan struct{}
	panics    atomic.Uint64
}

// New builds a pipeline. Call Start to launch the flusher.
func New(cfg Config) (*Pipeline, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() int64 { return time.Now().UnixNano() }
	}
	p := &Pipeline{
		cfg:   cfg,
		clock: clock,
		sink:  cfg.Sink,
		pool:  newPool(cfg.RecycleMaxFrames),
		batch: make([]*event.Event, cfg.BatchSize),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	p.sources = make([]sourceStats, cfg.Sources)
	p.cond = sync.NewCond(&p.mu)
	p.maxPending = int64(cfg.MaxPending)
	p.ro = NewReorderer(cfg.Sources, int64(cfg.Slack), int64(cfg.Lag), cfg.MaxPending)
	p.ro.SetLateHook(cfg.OnLate)
	return p, nil
}

// Start launches the flusher. Calling it more than once is a no-op.
func (p *Pipeline) Start() {
	if p.started.CompareAndSwap(false, true) {
		p.flusher()
	}
}

// Close stops the flusher, delivers everything that is left in timestamp
// order and returns. Stop the ETW sessions (so no callback is publishing)
// before calling it. Safe to call more than once. If the sink is wedged Close
// waits for it, so run it with a timeout.
func (p *Pipeline) Close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.mu.Lock()
		p.cond.Broadcast() // wake callbacks blocked in Acquire
		p.mu.Unlock()
		if p.started.Load() {
			close(p.quit)
			<-p.done
		}
		for !p.draining.CompareAndSwap(false, true) { // wait out an active drainer
			time.Sleep(50 * time.Microsecond)
		}
		p.run(true)
		p.draining.Store(false)
	})
}

// Stats returns a snapshot of all counters. Safe from any goroutine.
func (p *Pipeline) Stats() Stats {
	p.mu.Lock()
	s := Stats{Reorder: p.ro.Stats(), PendingHigh: p.pendingHigh}
	p.mu.Unlock()
	s.Panics = p.panics.Load()
	for i := range p.sources {
		src := &p.sources[i]
		s.Sources = append(s.Sources, SourceStats{
			ID:         SourceID(i),
			Acquired:   src.acquired.Load(),
			Published:  src.published.Load(),
			Blocked:    src.blocked.Load(),
			BlockedFor: time.Duration(src.blockedNs.Load()),
			Abandoned:  src.abandoned.Load(),
		})
	}
	return s
}

func (p *Pipeline) insert(sourceID SourceID, ev *event.Event) {
	if p.closed.Load() { // a callback that outlived the sources' shutdown
		p.pool.put(ev)
		return
	}
	now := p.clock()
	p.mu.Lock()
	p.ro.Add(sourceID, ev, now)
	l := p.ro.Len()
	p.pending.Store(int64(l))
	if l > p.pendingHigh {
		p.pendingHigh = l
	}
	p.mu.Unlock()
	p.added.Add(1)
	p.drain()
}

func (p *Pipeline) flusher() {
	defer close(p.done)
	t := time.NewTicker(p.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p.drain()
		case <-p.quit:
			return
		}
	}
}

// drain delivers whatever is ready, unless another goroutine is already doing
// it. The added counter closes the window in which that goroutine decided it
// was done just before our event arrived: if it moved, we go round again.
func (p *Pipeline) drain() {
	for {
		if !p.draining.CompareAndSwap(false, true) {
			return
		}
		seq := p.run(false)
		if p.beforeRelease != nil {
			p.beforeRelease()
		}
		p.draining.Store(false)
		if p.added.Load() == seq {
			return
		}
	}
}

// run delivers batches until a pop comes back short and returns the value of
// added observed before that pop. A short batch means nothing more was
// releasable at that moment, so no confirming empty pop is needed (it cost a
// lock and a clock read per event): anything inserted afterwards moves added,
// and drain goes round again. Only the drain-flag holder may call it.
func (p *Pipeline) run(all bool) uint64 {
	for {
		seq := p.added.Load()
		n := p.pop(all)
		for i := 0; i < n; i++ {
			ev := p.batch[i]
			p.batch[i] = nil
			p.dispatch(ev)
		}
		if n < len(p.batch) {
			return seq
		}
	}
}

// pop moves up to BatchSize releasable events from the reorderer into p.batch.
func (p *Pipeline) pop(all bool) int {
	n := 0
	p.mu.Lock()
	var wm int64 = math.MaxInt64
	if !all {
		wm = p.ro.Watermark(p.clock())
	}
	for n < len(p.batch) {
		ev, more := p.ro.Next(wm)
		if !more {
			break
		}
		p.batch[n] = ev
		n++
	}
	if n > 0 {
		p.cond.Broadcast() // room for blocked Acquire calls
	}
	p.mu.Unlock()
	return n
}

func (p *Pipeline) dispatch(ev *event.Event) {
	p.emitSeq++
	ev.Seq = p.emitSeq
	p.handle(ev)
	p.pool.put(ev)
}

func (p *Pipeline) handle(ev *event.Event) {
	defer func() {
		if v := recover(); v != nil {
			p.panics.Add(1)
			if p.cfg.OnPanic != nil {
				p.cfg.OnPanic(ev, v)
			}
		}
	}()
	p.sink.Handle(ev)
}

// SourceStats are the per-source counters.
type SourceStats struct {
	ID         SourceID
	Acquired   uint64        // events handed out
	Published  uint64        // events handed to the reorderer
	Abandoned  uint64        // acquired but released unpublished
	Blocked    uint64        // Acquire calls that had to wait for room
	BlockedFor time.Duration // total time spent waiting
}

// sourceStats holds one event source counters. The padding keeps each source on
// its own cache line. The callbacks of different sources run on different goroutines
// and would otherwise false-share.
type sourceStats struct {
	acquired  atomic.Uint64
	published atomic.Uint64
	abandoned atomic.Uint64
	blocked   atomic.Uint64
	blockedNs atomic.Int64
	_         [24]byte
}

// waitForRoom blocks until the reorderer has room or the pipeline closes.
// It reports whether there is room.
func (p *Pipeline) waitForRoom(stats *sourceStats) bool {
	stats.blocked.Add(1)
	t0 := time.Now()
	defer func() { stats.blockedNs.Add(int64(time.Since(t0))) }()
	for {
		if p.closed.Load() {
			return false
		}
		// Help: if nobody is delivering, becoming the drainer forces the
		// oldest events out. If someone is, its next pop wakes us.
		p.drain()

		p.mu.Lock()
		for p.ro.Len() >= p.cfg.MaxPending && !p.closed.Load() {
			p.cond.Wait() // woken by every pop and by Close
		}
		full := p.ro.Len() >= p.cfg.MaxPending
		p.mu.Unlock()
		if !full {
			return true
		}
	}
}

// Acquire returns a reset event for the caller to fill, or nil if the pipeline
// is closed. session is the index of the ETW session (or eBPF source) the
// event comes from.
//
// Acquire is where back-pressure happens: while the reorderer holds
// MaxPending events it blocks (helping to drain meanwhile) until there is
// room. The callback then stops returning, ETW's own session buffers absorb
// the burst, and the kernel drops only once they are exhausted (visible in the
// session's EventsLost). A sink that never returns therefore stalls the
// callbacks: supervise it with a watchdog.
//
// A non-nil event must be handed back with exactly one of Publish or Release,
// with the same session. Set Timestamp before Publish: the reorderer sorts on
// it. All methods are safe for concurrent use.
func (p *Pipeline) Acquire(sourceID SourceID) *event.Event {
	if p.closed.Load() {
		return nil
	}
	s := &p.sources[sourceID]
	if p.pending.Load() >= p.maxPending && !p.waitForRoom(s) {
		return nil
	}
	s.acquired.Add(1)
	return p.pool.get()
}

// Publish hands an event to the reorderer. The event belongs to the
// pipeline from here on and it should not be touched it again.
func (p *Pipeline) Publish(sourceID SourceID, ev *event.Event) {
	p.sources[sourceID].published.Add(1)
	p.insert(sourceID, ev)
}

// Release gives back an acquired event without publishing it.
func (p *Pipeline) Release(sourceID SourceID, ev *event.Event) {
	p.sources[sourceID].abandoned.Add(1)
	p.pool.put(ev)
}
