/*
 * Copyright 2026 Fibratus contributors
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
)

// ProcessKey uniquely identifies a process instance across PID reuse.
type ProcessKey struct {
	PID           uint32
	StartBootTime uint64
}

// HotEvent is a timestamped ring-buffer record received while the task
// iterator baseline is still being established.
type HotEvent struct {
	Key       ProcessKey
	Kind      uint32
	Timestamp uint64
	Comm      string
	Filename  string
	ExePath   string
	Cmdline   string
}

// Metrics accounts for every pressure-induced drop during startup/live capture.
type Metrics struct {
	PendingQueued   atomic.Uint64
	PendingDropped  atomic.Uint64
	RingbufDropped  atomic.Uint64
	EnrichmentMiss  atomic.Uint64
	ReplayApplied   atomic.Uint64
	SnapshotUpserts atomic.Uint64
}

// ProcessRecord is the reconciled userspace view of a process instance.
type ProcessRecord struct {
	Key      ProcessKey
	Comm     string
	Filename string
	ExePath  string
	Cmdline  string
	FromSnap bool
	FromHot  bool
}

// StartupReconciler prototypes the race-safe startup sequence:
// queue hot events, upsert iterator baseline by ProcessKey, replay pending
// events idempotently, then switch to live updates.
type StartupReconciler struct {
	mu       sync.Mutex
	pending  []HotEvent
	live     bool
	capacity int
	procs    map[ProcessKey]*ProcessRecord
	Metrics  Metrics
}

// NewStartupReconciler creates a reconciler with a bounded pending queue.
func NewStartupReconciler(capacity int) *StartupReconciler {
	if capacity <= 0 {
		capacity = 1024
	}
	return &StartupReconciler{
		capacity: capacity,
		procs:    make(map[ProcessKey]*ProcessRecord),
	}
}

// EnqueueHot queues a hot event while baseline capture is in progress.
// Returns false when the bounded queue drops the event.
func (r *StartupReconciler) EnqueueHot(ev HotEvent) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live {
		r.applyLocked(ev, true)
		return true
	}
	if len(r.pending) >= r.capacity {
		r.Metrics.PendingDropped.Add(1)
		return false
	}
	r.pending = append(r.pending, ev)
	r.Metrics.PendingQueued.Add(1)
	return true
}

// UpsertSnapshot installs an iterator baseline record keyed by ProcessKey.
func (r *StartupReconciler) UpsertSnapshot(rec ProcessRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.FromSnap = true
	existing, ok := r.procs[rec.Key]
	if !ok {
		cp := rec
		r.procs[rec.Key] = &cp
		r.Metrics.SnapshotUpserts.Add(1)
		return
	}
	mergeSnapshot(existing, rec)
	r.Metrics.SnapshotUpserts.Add(1)
}

// FinishBaseline replays queued hot events in order and switches to live mode.
func (r *StartupReconciler) FinishBaseline() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.pending {
		r.applyLocked(ev, true)
		r.Metrics.ReplayApplied.Add(1)
	}
	r.pending = nil
	r.live = true
}

// Get returns the reconciled process record for key, if present.
func (r *StartupReconciler) Get(key ProcessKey) (ProcessRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.procs[key]
	if !ok {
		return ProcessRecord{}, false
	}
	return *rec, true
}

// Size returns the number of reconciled process records.
func (r *StartupReconciler) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.procs)
}

// AccountRingbufDrop records a ring-buffer reserve failure observed in-kernel.
func (r *StartupReconciler) AccountRingbufDrop(n uint64) {
	if n == 0 {
		return
	}
	r.Metrics.RingbufDropped.Add(n)
}

// AccountEnrichmentMiss records a failed best-effort /proc enrichment.
func (r *StartupReconciler) AccountEnrichmentMiss() {
	r.Metrics.EnrichmentMiss.Add(1)
}

func (r *StartupReconciler) applyLocked(ev HotEvent, fromHot bool) {
	rec, ok := r.procs[ev.Key]
	if !ok {
		r.procs[ev.Key] = &ProcessRecord{
			Key:      ev.Key,
			Comm:     ev.Comm,
			Filename: ev.Filename,
			ExePath:  ev.ExePath,
			Cmdline:  ev.Cmdline,
			FromHot:  fromHot,
		}
		return
	}
	if ev.Comm != "" {
		rec.Comm = ev.Comm
	}
	if ev.Filename != "" {
		rec.Filename = ev.Filename
	}
	if ev.ExePath != "" {
		rec.ExePath = ev.ExePath
	}
	if ev.Cmdline != "" {
		rec.Cmdline = ev.Cmdline
	}
	if fromHot {
		rec.FromHot = true
	}
}

func mergeSnapshot(dst *ProcessRecord, src ProcessRecord) {
	dst.FromSnap = true
	if src.Comm != "" {
		dst.Comm = src.Comm
	}
	if src.Filename != "" {
		dst.Filename = src.Filename
	}
	if src.ExePath != "" {
		dst.ExePath = src.ExePath
	}
	if src.Cmdline != "" {
		dst.Cmdline = src.Cmdline
	}
}

// String returns a compact metrics summary for spike diagnostics.
func (m *Metrics) String() string {
	return fmt.Sprintf(
		"pending_queued=%d pending_dropped=%d ringbuf_dropped=%d enrichment_miss=%d replay_applied=%d snapshot_upserts=%d",
		m.PendingQueued.Load(),
		m.PendingDropped.Load(),
		m.RingbufDropped.Load(),
		m.EnrichmentMiss.Load(),
		m.ReplayApplied.Load(),
		m.SnapshotUpserts.Load(),
	)
}
