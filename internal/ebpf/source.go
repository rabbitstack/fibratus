//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ebpf

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/source"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPendingCap = 4096
	startupDrain      = 250 * time.Millisecond
)

var _ source.EventSource = (*EventSource)(nil)

// EventSource captures Linux process events through eBPF.
type EventSource struct {
	psnap     ps.Snapshotter
	config    *config.Config
	sequencer *event.Sequencer
	q         *event.Queue
	evts      chan *event.Event
	errs      chan error

	filter    filter.Filter
	listeners []event.Listener

	loader *loader
	reader *ringReader

	pending    []*event.Event
	pendingMu  sync.Mutex
	pendingCap int
	live       atomic.Bool

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// NewEventSource constructs the Linux eBPF event source.
func NewEventSource(psnap ps.Snapshotter, cfg *config.Config, _ *config.RulesCompileResult) source.EventSource {
	// Startup replay pushes queued events before the aggregator starts
	// consuming, so the channel must be able to absorb a full pending queue.
	evts := make(chan *event.Event, defaultPendingCap)
	return &EventSource{
		psnap:      psnap,
		config:     cfg,
		sequencer:  event.NewSequencer(),
		evts:       evts,
		q:          event.NewQueueWithChannel(evts, false, cfg.ForwardMode),
		errs:       make(chan error, 256),
		listeners:  make([]event.Listener, 0),
		pendingCap: defaultPendingCap,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
}

func (e *EventSource) Open(cfg *config.Config) error {
	if cfg != nil {
		e.config = cfg
	}
	if e.config == nil {
		return fmt.Errorf("missing configuration")
	}

	report, err := checkRuntimeSupport()
	if err != nil {
		if report != nil {
			return fmt.Errorf("eBPF prerequisites: %w", err)
		}
		return err
	}
	log.Infof("eBPF prerequisites ok: kernel=%s btf=%s ringbuf=%v iter=%v",
		report.KernelRelease, report.BTFPath, report.RingbufOK, report.IterOK)

	ldr, err := loadCollections()
	if err != nil {
		return err
	}
	e.loader = ldr

	rd, err := newRingReader(ldr.eventsMap())
	if err != nil {
		_ = ldr.Close()
		return err
	}
	e.reader = rd

	go e.consume()

	if err := ldr.attachPrograms(); err != nil {
		e.Close()
		return err
	}

	if err := ldr.runTaskIterator(); err != nil {
		e.Close()
		return err
	}

	time.Sleep(startupDrain)
	e.finishBaseline()
	ringbufDrops.Add(int64(ldr.dropCount()))
	log.Infof("eBPF process source is live; %s", e.startupSummary())
	return nil
}

func (e *EventSource) Close() error {
	var err error
	e.once.Do(func() {
		close(e.stop)
		started := e.reader != nil
		if e.reader != nil {
			_ = e.reader.Close()
		}
		if e.loader != nil {
			err = e.loader.Close()
		}
		if started {
			<-e.done
		}
		if e.sequencer != nil {
			_ = e.sequencer.Shutdown()
		}
		if e.q != nil {
			e.q.Close()
		}
	})
	return err
}

func (e *EventSource) Errors() <-chan error { return e.errs }

func (e *EventSource) Events() <-chan *event.Event { return e.q.Events() }

func (e *EventSource) SetFilter(f filter.Filter) { e.filter = f }

func (e *EventSource) RegisterEventListener(lis event.Listener) {
	e.listeners = append(e.listeners, lis)
	if e.q != nil {
		e.q.RegisterListener(lis)
	}
}

func (e *EventSource) consume() {
	defer close(e.done)
	for {
		raw, err := e.reader.Read()
		if err != nil {
			if isRingClosed(err) {
				return
			}
			select {
			case <-e.stop:
				return
			case e.errs <- err:
			default:
			}
			continue
		}
		e.handleRecord(raw)
	}
}

func (e *EventSource) handleRecord(raw []byte) {
	rec, err := decodeRawEvent(raw)
	if err != nil {
		parseErrors.Add(1)
		return
	}
	if rec.Type == snapshotType {
		e.handleSnapshot(rec)
		return
	}
	typ := rec.eventType()
	if typ == event.UnknownType {
		eventsUnknown.Add(1)
		return
	}
	if e.config != nil && !e.config.EventSource.EventExists(typ.ID()) {
		eventsUnknown.Add(1)
		return
	}

	evt := rec.toEvent()
	if typ == event.Execve || typ == event.Clone {
		enrichEvent(evt)
	}

	if !e.live.Load() && e.enqueuePending(evt) {
		return
	}
	e.dispatch(evt)
}

func (e *EventSource) handleSnapshot(rec rawEvent) {
	if e.live.Load() {
		lateSnapshots.Add(1)
		return
	}
	exe, cmdline, err := enrichFromProc(uint64(rec.TGID))
	if err != nil {
		enrichmentMiss.Add(1)
	}
	upsertSnapshot(e.psnap, snapshotFromRaw(rec, exe, cmdline))
}

func (e *EventSource) enqueuePending(evt *event.Event) bool {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	if e.live.Load() {
		return false
	}
	if len(e.pending) >= e.pendingCap {
		pendingDropped.Add(1)
		return false
	}
	e.pending = append(e.pending, evt)
	pendingQueued.Add(1)
	return true
}

// finishBaseline replays queued hot events in ring-buffer order and then
// switches to live dispatch. New records keep landing in the pending queue
// while a replay round runs, so loop until the queue drains before flipping
// live. This guarantees replayed and live events preserve global ring-buffer
// order.
func (e *EventSource) finishBaseline() {
	for {
		e.pendingMu.Lock()
		pending := e.pending
		e.pending = nil
		if len(pending) == 0 {
			e.live.Store(true)
			e.pendingMu.Unlock()
			return
		}
		e.pendingMu.Unlock()
		for _, evt := range pending {
			e.dispatch(evt)
			replayApplied.Add(1)
		}
	}
}

func (e *EventSource) dispatch(evt *event.Event) {
	evt.Seq = e.sequencer.Get()
	applyProcessState(e.psnap, evt)
	eventsProcessed.Add(1)

	if e.config != nil {
		if e.config.EventSource.ExcludeEvent(evt.Type.ID()) {
			eventsExcluded.Add(1)
			return
		}
		if e.config.EventSource.ExcludeImage(evt.PS) {
			eventsExcluded.Add(1)
			return
		}
		if evt.IsDropped(e.config.IsCaptureSet()) {
			eventsExcluded.Add(1)
			return
		}
	}
	if e.filter != nil && !e.filter.Eval(evt) {
		return
	}
	e.sequencer.Increment()
	if err := e.q.Push(evt); err != nil {
		select {
		case e.errs <- err:
		default:
		}
	}
}

func (e *EventSource) startupSummary() string {
	return fmt.Sprintf("pending_queued=%d pending_dropped=%d replay_applied=%d snapshot_upserts=%d",
		pendingQueued.Value(), pendingDropped.Value(), replayApplied.Value(), snapshotUpserts.Value())
}
