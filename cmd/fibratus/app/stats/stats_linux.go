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

package stats

// Stats stores runtime statistics that are retrieved from the expvar endpoint.
// Field order is the order the table renders in, so counters are grouped by the
// stage they describe: capture, then the kernel-side drops worth alerting on,
// then the startup handover, then the rule engine.
type Stats struct {
	EventsProcessed int `json:"ebpf.events.processed"`
	EventsExcluded  int `json:"ebpf.events.excluded"`
	EventsUnknown   int `json:"ebpf.events.unknown"`
	EventsParseErrs int `json:"ebpf.events.parse.errors"`

	RingbufDrops  int `json:"ebpf.ringbuf.drops"`
	ApproverDrops int `json:"ebpf.approver.drops"`

	EnrichmentMiss int `json:"ebpf.enrichment.miss"`

	StartupPendingQueued   int `json:"ebpf.startup.pending.queued"`
	StartupPendingDropped  int `json:"ebpf.startup.pending.dropped"`
	StartupReplayApplied   int `json:"ebpf.startup.replay.applied"`
	StartupSnapshotUpserts int `json:"ebpf.startup.snapshot.upserts"`
	StartupSnapshotLate    int `json:"ebpf.startup.snapshot.late"`

	FiltersCount  int            `json:"filter.filters.count"`
	FilterMatches map[string]int `json:"filter.matches"`

	AggregatorBatchEvents  int `json:"aggregator.batch.events"`
	AggregatorFlushesCount int `json:"aggregator.flushes.count"`
	AggregatorEventErrors  int `json:"aggregator.event.errors"`
}
