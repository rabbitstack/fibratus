package pipeline

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// ShedClass is the shedding priority of an event.
type ShedClass uint8

const (
	// ClassState events (process, thread, image load, ...) feed the state
	// store and symbolization. They are never shed by the watermarks; they can
	// only be lost if the ring is completely full for longer than
	// ShedConfig.CriticalWait, and that is counted loudly (DroppedState).
	ClassState ShedClass = iota
	// ClassNormal events are shed only under heavy pressure.
	ClassNormal
	// ClassNoisy events (file, registry, ...) are shed first.
	ClassNoisy
)

// Classifier maps an event type to its shedding class. It runs
// for every event so keep it a table lookup or a few compares.
type Classifier func(event.Type) ShedClass

// ShedConfig tunes load shedding. Thresholds are fractions of the ring size.
//
// Level 0 admits everything. Level 1 (entered at Enter1, left below Exit1)
// sheds ClassNoisy. Level 2 (entered at Enter2, left below Exit2) also sheds
// ClassNormal. The gap between enter and exit is the hysteresis that stops the
// level from flapping around a threshold.
//
// Independently of the level, non-state events can never use the last
// ReserveFrac of the ring, which is headroom reserved for ClassState.
type ShedConfig struct {
	// SampleEvery is how many Acquire calls pass between occupancy samples.
	// Sampling reads the consumer's cache line, so it is amortized.
	SampleEvery int

	Enter1, Exit1 float64
	Enter2, Exit2 float64

	// ReserveFrac is the ring fraction reserved for ClassState events.
	ReserveFrac float64

	// CriticalWait bounds how long a ClassState Acquire may wait (yielding)
	// for a free slot when the ring is completely full. Zero means don't wait.
	// This is the only place the ETW callback can block; keep it small.
	CriticalWait time.Duration
}

// DefaultShedConfig returns sensible starting values.
func DefaultShedConfig() ShedConfig {
	return ShedConfig{
		SampleEvery:  32,
		Enter1:       0.70,
		Exit1:        0.50,
		Enter2:       0.90,
		Exit2:        0.75,
		ReserveFrac:  1.0 / 16,
		CriticalWait: 100 * time.Microsecond,
	}
}

func (c ShedConfig) validate() error {
	switch {
	case c.SampleEvery < 1:
		return errors.New("pipeline: SampleEvery must be >= 1")
	case !(0 < c.Exit1 && c.Exit1 < c.Enter1 && c.Enter1 < c.Enter2 && c.Enter2 <= 1):
		return fmt.Errorf("pipeline: need 0 < Exit1 < Enter1 < Enter2 <= 1, got %v %v %v", c.Exit1, c.Enter1, c.Enter2)
	case !(c.Exit1 < c.Exit2 && c.Exit2 < c.Enter2):
		return fmt.Errorf("pipeline: need Exit1 < Exit2 < Enter2, got %v %v %v", c.Exit1, c.Exit2, c.Enter2)
	case c.ReserveFrac < 0 || c.ReserveFrac > 0.5:
		return errors.New("pipeline: ReserveFrac must be within [0, 0.5]")
	case c.CriticalWait < 0:
		return errors.New("pipeline: CriticalWait must be >= 0")
	}
	return nil
}

// ProducerStats is a snapshot of a producer's counters.
type ProducerStats struct {
	Published     uint64 // events handed to the consumer
	DroppedNormal uint64 // shed: ClassNormal
	DroppedNoisy  uint64 // shed: ClassNoisy
	DroppedState  uint64 // LOST state events: ring full for longer than CriticalWait
	ShedLevel     int    // current shedding level (0, 1 or 2)
	Transitions   uint64 // shedding level changes
	Occupancy     int
	Capacity      int
}

// Producer is the facade an ETW callback uses to hand events to the pipeline.
// One Producer belongs to one session and must be used from one goroutine.
//
//	ev := prod.Acquire(typ)
//	if ev == nil {
//	    return // shed or lost; already counted
//	}
//	// fill ev in place: Timestamp, PID, Tid, Params, ...
//	prod.Publish()
type Producer struct {
	ring        *Ring[event.Event]
	classify    Classifier
	sampleEvery uint32
	tick        uint32
	level       uint8

	enter1, exit1, enter2, exit2 uint64
	reserve                      uint64
	criticalWait                 time.Duration

	shed          [3]atomic.Uint64 // indexed by Class. ClassState is never shed
	criticalDrops atomic.Uint64
	levelPub      atomic.Uint32
	transitions   atomic.Uint64
}

// NewProducer wraps ring (whose single producer is the caller) with
// classification and load shedding.
func NewProducer(r *Ring[event.Event], classify Classifier, cfg ShedConfig) (*Producer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if classify == nil {
		classify = func(event.Type) ShedClass { return ClassNormal }
	}
	size := float64(r.size)
	return &Producer{
		ring:         r,
		classify:     classify,
		sampleEvery:  uint32(cfg.SampleEvery),
		enter1:       uint64(cfg.Enter1 * size),
		exit1:        uint64(cfg.Exit1 * size),
		enter2:       uint64(cfg.Enter2 * size),
		exit2:        uint64(cfg.Exit2 * size),
		reserve:      uint64(cfg.ReserveFrac * size),
		criticalWait: cfg.CriticalWait,
	}, nil
}

// Acquire returns a reset slot for the event to fill in place, or nil if the
// event was shed or lost. Never call Acquire twice without Publish in between
// unless you intend to abandon the first slot (it is simply handed out again).
// A non-nil result must be followed by Publish.
func (p *Producer) Acquire(t event.Type) *event.Event {
	class := p.classify(t)
	if class > ClassNoisy {
		class = ClassNoisy
	}

	p.tick++
	if p.tick >= p.sampleEvery {
		p.tick = 0
		p.sample()
	}

	if class == ClassState {
		return p.acquireState()
	}
	if int(class)+int(p.level) >= 3 { // level 1 sheds noisy, level 2 sheds noisy+normal
		p.shed[class].Add(1)
		return nil
	}
	slot := p.ring.slot(p.reserve)
	if slot == nil { // ran into the reserve: only state events may use it
		p.shed[class].Add(1)
		return nil
	}
	slot.Reset()
	return slot
}

// acquireState is the only path that may wait, and only when the ring is
// completely full. The wait is bounded; on expiry the event is lost and
// counted in DroppedState.
func (p *Producer) acquireState() *event.Event {
	slot := p.ring.slot(0)
	if slot == nil && p.criticalWait > 0 {
		deadline := time.Now().Add(p.criticalWait)
		for slot == nil && time.Now().Before(deadline) {
			runtime.Gosched()
			slot = p.ring.slot(0)
		}
	}
	if slot == nil {
		p.criticalDrops.Add(1)
		return nil
	}
	slot.Reset()
	return slot
}

// Publish hands the slot returned by the last successful Acquire to the
// consumer.
func (p *Producer) Publish() { p.ring.Publish() }

// sample reads the occupancy and moves the shedding level with hysteresis.
func (p *Producer) sample() {
	occ := p.ring.producerLen()
	lvl := p.level
	for {
		switch {
		case lvl < 2 && occ >= p.enter2:
			lvl = 2
		case lvl < 1 && occ >= p.enter1:
			lvl = 1
		case lvl == 2 && occ < p.exit2:
			lvl = 1
		case lvl == 1 && occ < p.exit1:
			lvl = 0
		default:
			if lvl != p.level {
				p.level = lvl
				p.levelPub.Store(uint32(lvl))
				p.transitions.Add(1)
			}
			return
		}
	}
}

// Stats returns a snapshot of the counters. Safe from any goroutine.
func (p *Producer) Stats() ProducerStats {
	return ProducerStats{
		Published:     p.ring.tail.Load(),
		DroppedNormal: p.shed[ClassNormal].Load(),
		DroppedNoisy:  p.shed[ClassNoisy].Load(),
		DroppedState:  p.criticalDrops.Load(),
		ShedLevel:     int(p.levelPub.Load()),
		Transitions:   p.transitions.Load(),
		Occupancy:     p.ring.Len(),
		Capacity:      p.ring.Cap(),
	}
}
