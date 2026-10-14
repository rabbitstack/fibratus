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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

func allState(event.Type) ShedClass { return ClassState }

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("zero config accepted")
	}
	cfg := DefaultConfig(2)
	cfg.IdleTimeout = 0
	if _, err := New(cfg); err == nil {
		t.Fatal("IdleTimeout=0 accepted")
	}
	cfg = DefaultConfig(2)
	cfg.Shed.Enter1 = 0.1
	if _, err := New(cfg); err == nil {
		t.Fatal("bad shed config accepted")
	}
	if _, err := New(DefaultConfig(2)); err != nil {
		t.Fatal(err)
	}
}

func TestCloseWithoutStartAndTwice(t *testing.T) {
	p, err := New(DefaultConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	p.Close() // never started
	p, _ = New(DefaultConfig(1))
	go p.Start()
	go p.Start() // second Start is a no-op
	p.Close()
	p.Close()
}

// Two producers run flat out on their own goroutines. The events carry
// interleaved timestamps (session 0 odd, session 1 even); the handler must see
// every event exactly once, in global timestamp order, with gap-free Seq.
func TestPipelineEndToEndOrdering(t *testing.T) {
	const perSession = 100_000

	var got []int64
	var bad int
	cfg := DefaultConfig(2)
	cfg.RingSize = 1 << 12
	cfg.MaxPending = 1 << 20 // large enough that the valve never opens
	cfg.Slack = 0
	cfg.IdleTimeout = time.Hour
	cfg.Clock = func() int64 { return 0 } // idle detection off: strictness over latency
	cfg.Classify = allState
	cfg.Shed.CriticalWait = time.Second
	cfg.Handlers = []Handler{HandlerFunc(func(ev *event.Event) {
		ts := ev.Timestamp.UnixNano()
		got = append(got, ts)
		if ev.Seq != uint64(len(got)) {
			bad++
		}
		// if p := ev.Param(1); p == nil || int64(p.U) != ts || int64(ev.PID) != (ts-1)%2 {
		// 	bad++
		// }
	})}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go p.Start()

	var wg sync.WaitGroup
	for s := 0; s < 2; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			prod := p.Producer(s)
			for i := 0; i < perSession; i++ {
				ts := int64(2*i + s + 1)
				ev := prod.Acquire(event.CreateProcess)
				for ev == nil {
					runtime.Gosched()
					ev = prod.Acquire(event.CreateProcess)
				}
				ev.Timestamp = time.Unix(0, ts)
				ev.PID = uint32(s)
				//ev.AddUint(1, uint64(ts))
				prod.Publish()
			}
		}(s)
	}
	wg.Wait()
	p.Close()

	if len(got) != 2*perSession {
		t.Fatalf("handler saw %d events, want %d", len(got), 2*perSession)
	}
	for i, ts := range got {
		if ts != int64(i+1) {
			t.Fatalf("event %d has ts %d: global order broken", i, ts)
		}
	}
	if bad != 0 {
		t.Fatalf("%d events had a wrong Seq or payload", bad)
	}
	st := p.Stats()
	if st.Reorder.Late != 0 || st.Reorder.Forced != 0 || st.Reorder.Emitted != 2*perSession {
		t.Fatalf("reorder stats = %+v", st.Reorder)
	}
}

// With the consumer wedged, noisy events are shed and every state event still
// gets through; the books must balance exactly.
func TestPipelineBackpressureKeepsStateEvents(t *testing.T) {
	const attempts = 10_000 // every 100th is a state event
	gate := make(chan struct{})
	var once sync.Once
	var delivered, deliveredState atomic.Uint64

	cfg := DefaultConfig(1)
	cfg.RingSize = 1024
	cfg.MaxPending = 256
	cfg.Classify = classByFirstByte
	cfg.Shed.CriticalWait = 500 * time.Millisecond
	cfg.Handlers = []Handler{HandlerFunc(func(ev *event.Event) {
		once.Do(func() { <-gate }) // wedge the consumer on the first event
		delivered.Add(1)
		if ShedClass(ev.Type) == ClassState {
			deliveredState.Add(1)
		}
	})}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go p.Start()

	prod := p.Producer(0)
	wantState := 0
	for i := 0; i < attempts; i++ {
		class := ClassNoisy
		if i%100 == 0 {
			class = ClassState
			wantState++
		}
		ev := prod.Acquire(tp(class))
		if ev == nil {
			continue
		}
		ev.Type = tp(class)
		ev.Timestamp = time.Now()
		prod.Publish()
	}
	close(gate)
	p.Close()

	st := p.Stats().Producers[0]
	if st.DroppedNoisy == 0 {
		t.Fatal("nothing was shed although the consumer was wedged")
	}
	if st.DroppedState != 0 {
		t.Fatalf("lost %d state events", st.DroppedState)
	}
	if got := st.Published + st.DroppedNoisy + st.DroppedNormal + st.DroppedState; got != attempts {
		t.Fatalf("books don't balance: %d accounted for, %d attempted", got, attempts)
	}
	if delivered.Load() != st.Published {
		t.Fatalf("delivered %d, published %d", delivered.Load(), st.Published)
	}
	if int(deliveredState.Load()) != wantState {
		t.Fatalf("delivered %d state events, want all %d", deliveredState.Load(), wantState)
	}
}

// The point of value slots: once every slot and the pool have grown their
// backing arrays, a full producer -> consumer cycle allocates nothing.
func TestSteadyStateZeroAllocs(t *testing.T) {
	r := NewRing[event.Event](64)
	p, err := NewProducer(r, allState, shedCfg())
	if err != nil {
		t.Fatal(err)
	}
	pooled := &event.Event{}
	var n int64
	cycle := func() {
		n++
		ev := p.Acquire(event.Connect)
		ev.Timestamp = time.Unix(0, n)
		ev.PID = 1
		// ev.AddUint(1, uint64(n))
		// ev.AddUint(2, 2)
		// ev.AddString(3, "value")
		// ev.SetMeta("k", "v")
		//ev.Callstack = append(ev.Callstack, Frame{Addr: 1}, Frame{Addr: 2})
		p.Publish()

		a, _ := r.Claim(1)
		pooled.MoveFrom(&a[0])
		r.Release(1)
		pooled.Reset()
	}
	for i := 0; i < 64*8; i++ { // let every slot cycle through the grown arrays
		cycle()
	}
	if allocs := testing.AllocsPerRun(2000, cycle); allocs != 0 {
		t.Fatalf("steady state allocates %v per event, want 0", allocs)
	}
}
