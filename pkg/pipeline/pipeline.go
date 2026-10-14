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
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// Handler is entrypoint to the processing chain. It can contain multiple stages
// that run sequentially on the pipeline goroutine, in order, for every event.
//
// The event is recycled as soon as the handler returns. A stage that keeps the
// event (sequence rules holding partial matches, async sinks, anything handed
// to another goroutine) must clone the event first.
type Handler interface {
	Handle(*event.Event)
}

// Config configures a Pipeline. Start from DefaultConfig.
type Config struct {
	// Producers is the number of rings and producers.
	Producers int
	// RingSize is the slot count of each producer's ring (rounded up to a
	// power of two).
	RingSize int

	// MaxPending bounds the events held by the reorderer (and so the pooled
	// events alive). Memory is bounded by RingSize*Producers + MaxPending.
	MaxPending int

	// BatchSize is the maximum number of slots claimed per ring per pass.
	BatchSize int

	// Slack is the skew the reorderer tolerates before declaring an event
	// late. The larger the slack, the more conservative the reorderer is:
	// it waits longer, but has a better chance of catching events delivered
	// out of timestamp order.
	Slack time.Duration

	// Lag is the longest an event can sit before it is delivered to the reorderer.
	Lag time.Duration

	// IdleSleep is the consumer's sleep when it has nothing to do (after a
	// short spin and a few yields).
	IdleSleep time.Duration

	// FreeListSize caps how many empty events are kept for reuse. Default
	// is 4096. 0 means the default, while negative value means unbounded.
	FreeListSize int

	// RecycleMaxParams and RecycleMaxFrames stop one outlier from pinning
	// memory forever: a recycled event whose params exceeded RecycleMaxParams
	// (default 32) or whose call stack capacity exceeds RecycleMaxFrames
	// (default 64) gives that storage back instead of keeping it.
	RecycleMaxParams int
	RecycleMaxFrames int

	Classifier Classifier
	Handler    Handler

	Shed ShedConfig

	// Clock returns the current time in the same domain as Event.Timestamp
	// (UnixNano). Defaults to time.Now.
	Clock func() int64
}

// DefaultConfig returns a configuration to start tuning from.
func DefaultConfig(producers int) Config {
	return Config{
		Producers:        producers,
		RingSize:         1 << 16,
		MaxPending:       1 << 16,
		BatchSize:        256,
		FreeListSize:     4096,
		Lag:              2650 * time.Millisecond,
		Slack:            100 * time.Millisecond,
		IdleSleep:        50 * time.Microsecond,
		Shed:             DefaultShedConfig(),
		RecycleMaxParams: 12,
		RecycleMaxFrames: 64,
	}
}

func (c *Config) validate() error {
	switch {
	case c.Producers < 1:
		return errors.New("pipeline: Producers must be >= 1")
	case c.RingSize < 2:
		return errors.New("pipeline: RingSize must be >= 2")
	case c.MaxPending < 1:
		return errors.New("pipeline: MaxPending must be >= 1")
	case c.BatchSize < 1:
		return errors.New("pipeline: BatchSize must be >= 1")
	case c.Slack < 0 || c.IdleSleep < 0:
		return errors.New("pipeline: Slack and IdleSleep must be >= 0")
	case c.Lag < c.Slack:
		return fmt.Errorf("reorderer lag (%s) must not be smaller than slack (%s)", c.Lag, c.Slack)
	}
	if err := c.Shed.validate(); err != nil {
		return fmt.Errorf("shed config: %w", err)
	}
	return nil
}

// Stats is a snapshot of the whole pipeline.
type Stats struct {
	Producers []ProducerStats
	Reorder   ReorderStats
	Free      FreeStats
}

// FreeStats describes the event free list.
type FreeStats struct {
	Len     int    // empty events currently held for reuse
	Dropped uint64 // events released to the GC because the list was full
	Trimmed uint64 // recycled events that gave back oversized params or call stack
}

// Pipeline owns the rings, the reorderer and the consumer goroutine.
type Pipeline struct {
	cfg     Config
	clock   func() int64
	rings   []*Ring[event.Event]
	prods   []*Producer
	ro      *Reorderer
	handler Handler

	free    []*event.Event // recycled events that are touched only by the consumer goroutine
	emitSeq uint64

	started atomic.Bool
	stop    atomic.Bool
	done    chan struct{}
	pending atomic.Int64

	freeLen     atomic.Int64
	freeDropped atomic.Uint64
	freeTrimmed atomic.Uint64
}

// New builds a pipeline. Call Start to launch the consumer.
func New(cfg Config) (*Pipeline, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	switch {
	case cfg.FreeListSize == 0:
		cfg.FreeListSize = 4096
	case cfg.FreeListSize < 0:
		cfg.FreeListSize = math.MaxInt
	}
	if cfg.RecycleMaxParams <= 0 {
		cfg.RecycleMaxParams = 32
	}
	if cfg.RecycleMaxFrames <= 0 {
		cfg.RecycleMaxFrames = 64
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() int64 { return time.Now().UnixNano() }
	}

	p := &Pipeline{
		cfg:     cfg,
		clock:   clock,
		handler: cfg.Handler,
		done:    make(chan struct{}),
	}

	for i := 0; i < cfg.Producers; i++ {
		r := NewRing[event.Event](cfg.RingSize)
		prod, err := NewProducer(r, cfg.Classifier, cfg.Shed)
		if err != nil {
			return nil, err
		}
		p.rings = append(p.rings, r)
		p.prods = append(p.prods, prod)
	}

	p.ro = NewReorderer(cfg.Producers, int64(cfg.Slack), int64(cfg.Lag), cfg.MaxPending)

	return p, nil
}

// Producer returns the producer at index i. Hand it to the goroutine that
// runs that event collection. It must not be shared between goroutines.
func (p *Pipeline) Producer(i ProducerID) *Producer { return p.prods[i] }

func (p *Pipeline) AcquireEvent(i ProducerID, t event.Type) (*event.Event, *Producer, error) {
	producer := p.Producer(i)
	evt := producer.Acquire(t)
	if evt == nil {
		return nil, producer, ErrRingNoSlots
	}
	return evt, producer, nil
}

// Start launches the consumer loop. Calling it more than once is a no-op.
func (p *Pipeline) Start() {
	if p.started.CompareAndSwap(false, true) {
		p.run()
	}
}

// Close drains the rings, flushes the reorderer in timestamp order through the
// stages and stops the consumer. Safe to call more than once.
func (p *Pipeline) Close() {
	p.stop.Store(true)
	if p.started.Load() {
		<-p.done
	}
}

// Stats returns a snapshot of all counters. Safe from any goroutine.
func (p *Pipeline) Stats() Stats {
	s := Stats{Reorder: p.ro.Stats()}
	s.Reorder.Pending = int(p.pending.Load())
	s.Free = FreeStats{Len: int(p.freeLen.Load()), Dropped: p.freeDropped.Load(), Trimmed: p.freeTrimmed.Load()}
	for _, prod := range p.prods {
		s.Producers = append(s.Producers, prod.Stats())
	}
	return s
}

func (p *Pipeline) run() {
	defer close(p.done)
	w := waiter{sleep: p.cfg.IdleSleep}
	for {
		// Read the stop flag before draining: once it is set no producer is
		// running, so one more full pass sees everything that will ever arrive.
		stopping := p.stop.Load()

		ingested := 0
		for s := range p.rings {
			ingested += p.ingest(s)
		}
		emitted := p.emit(p.clock())
		p.pending.Store(int64(p.ro.Len()))

		if stopping && ingested == 0 && p.ringsEmpty() {
			p.flush()
			p.pending.Store(0)
			return
		}
		if ingested+emitted == 0 {
			w.wait()
		} else {
			w.reset()
		}
	}
}

// ingest moves one batch from ring s into the reorderer. Each claimed slot is
// swapped into a pooled event and released right away, so a slot is never held
// longer than this loop and the ring keeps flowing even while events wait in
// the reorderer.
func (p *Pipeline) ingest(s int) int {
	room := p.cfg.MaxPending - p.ro.Len()
	if room <= 0 {
		return 0 // reorderer full: leave events in the ring, producers will shed
	}
	r := p.rings[s]
	a, b := r.Claim(min(p.cfg.BatchSize, room))
	n := len(a) + len(b)
	if n == 0 {
		return 0
	}
	now := p.clock()
	for i := range a {
		p.take(s, &a[i], now)
	}
	for i := range b {
		p.take(s, &b[i], now)
	}
	r.Release(n)
	return n
}

func (p *Pipeline) take(s int, slot *event.Event, now int64) {
	ev := p.get()
	ev.MoveFrom(slot)
	p.ro.Add(s, ev, now)
}

// emit releases every event the watermark allows through the handler chain.
func (p *Pipeline) emit(now int64) int {
	wm := p.ro.Watermark(now)
	n := 0
	for {
		ev, more := p.ro.Next(wm)
		if !more {
			return n
		}
		p.dispatch(ev)
		n++
	}
}

// flush releases everything that is left, in order, ignoring the watermark.
func (p *Pipeline) flush() {
	for {
		ev, more := p.ro.Next(math.MaxInt64)
		if !more {
			return
		}
		p.dispatch(ev)
	}
}

func (p *Pipeline) dispatch(ev *event.Event) {
	p.emitSeq++
	ev.Seq = p.emitSeq

	p.handler.Handle(ev)

	ev.Reset()
	p.recycle(ev, len(ev.Params) > p.cfg.RecycleMaxParams)
}

// recycle returns an empty event to the free list, within the cap, after
// letting go of storage an outlier grew.
func (p *Pipeline) recycle(ev *event.Event, bigParams bool) {
	if len(p.free) >= p.cfg.FreeListSize {
		p.freeDropped.Add(1)
		return
	}
	trimmed := false
	if bigParams {
		ev.Params, trimmed = nil, true
	}
	if cap(ev.Callstack) > p.cfg.RecycleMaxFrames {
		ev.Callstack, trimmed = nil, true
	}
	if trimmed {
		p.freeTrimmed.Add(1)
	}
	p.free = append(p.free, ev)
}

func (p *Pipeline) get() *event.Event {
	if n := len(p.free); n > 0 {
		ev := p.free[n-1]
		p.free[n-1] = nil
		p.free = p.free[:n-1]
		return ev
	}
	return new(event.Event)
}

func (p *Pipeline) ringsEmpty() bool {
	for _, r := range p.rings {
		if r.Len() != 0 {
			return false
		}
	}
	return true
}

// waiter is the consumer's idle strategy: spin briefly, then yield, then sleep.
// It never burns a core while the system is quiet, and it re-polls often
// enough that the reorderer's idle timeout fires on time.
type waiter struct {
	n     int
	sleep time.Duration
}

func (w *waiter) reset() { w.n = 0 }

func (w *waiter) wait() {
	if w.n < 1<<30 {
		w.n++
	}
	switch {
	case w.n <= 32:
		// spin: poll again immediately
	case w.n <= 64:
		runtime.Gosched()
	case w.sleep > 0:
		time.Sleep(w.sleep)
	default:
		runtime.Gosched()
	}
}
