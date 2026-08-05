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

import "testing"

func TestStartupReconcilerRaceSafeBaseline(t *testing.T) {
	r := NewStartupReconciler(8)

	keyA := ProcessKey{PID: 42, StartBootTime: 100}
	keyB := ProcessKey{PID: 42, StartBootTime: 200} // PID reuse with different start time

	if !r.EnqueueHot(HotEvent{Key: keyA, Kind: 1, Comm: "hot-a", Filename: "/bin/hot-a"}) {
		t.Fatal("expected hot event to be queued")
	}

	r.UpsertSnapshot(ProcessRecord{Key: keyA, Comm: "snap-a"})
	r.UpsertSnapshot(ProcessRecord{Key: keyB, Comm: "snap-b"})
	r.FinishBaseline()

	gotA, ok := r.Get(keyA)
	if !ok {
		t.Fatal("missing keyA after baseline")
	}
	if gotA.Comm != "hot-a" {
		t.Fatalf("keyA comm=%q want hot-a (hot replay should win over snapshot comm)", gotA.Comm)
	}
	if gotA.Filename != "/bin/hot-a" {
		t.Fatalf("keyA filename=%q", gotA.Filename)
	}
	if !gotA.FromSnap || !gotA.FromHot {
		t.Fatalf("keyA flags snap=%v hot=%v", gotA.FromSnap, gotA.FromHot)
	}

	gotB, ok := r.Get(keyB)
	if !ok {
		t.Fatal("missing keyB after baseline")
	}
	if gotB.Comm != "snap-b" {
		t.Fatalf("keyB comm=%q want snap-b", gotB.Comm)
	}

	// Live update for reused PID must not clobber the other instance.
	r.EnqueueHot(HotEvent{Key: keyB, Kind: 1, Comm: "live-b", ExePath: "/bin/live-b"})
	gotB, _ = r.Get(keyB)
	if gotB.Comm != "live-b" || gotB.ExePath != "/bin/live-b" {
		t.Fatalf("live update failed: %+v", gotB)
	}
	gotA, _ = r.Get(keyA)
	if gotA.Comm != "hot-a" {
		t.Fatalf("PID reuse clobbered keyA: %+v", gotA)
	}
}

func TestStartupReconcilerPendingBackpressure(t *testing.T) {
	r := NewStartupReconciler(2)
	key := ProcessKey{PID: 1, StartBootTime: 1}
	if !r.EnqueueHot(HotEvent{Key: key, Kind: 1}) {
		t.Fatal("first enqueue failed")
	}
	if !r.EnqueueHot(HotEvent{Key: key, Kind: 1}) {
		t.Fatal("second enqueue failed")
	}
	if r.EnqueueHot(HotEvent{Key: key, Kind: 1}) {
		t.Fatal("expected bounded queue drop")
	}
	if r.Metrics.PendingDropped.Load() != 1 {
		t.Fatalf("pending_dropped=%d want 1", r.Metrics.PendingDropped.Load())
	}
}
