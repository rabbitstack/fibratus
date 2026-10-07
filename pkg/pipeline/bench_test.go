package pipeline

import (
	"runtime"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// Producer fills value slots in place; consumer claims and releases them.
func BenchmarkRingValueSlots(b *testing.B) {
	r := NewRing[event.Event](1 << 12)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; {
			s := r.Slot()
			if s == nil {
				runtime.Gosched()
				continue
			}
			s.Reset()
			s.PID = uint32(i)
			// s.AddUint(1, uint64(i))
			// s.AddUint(2, 2)
			// s.AddString(3, "value")
			r.Publish()
			i++
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for got := 0; got < b.N; {
		x, y := r.Claim(256)
		n := len(x) + len(y)
		if n == 0 {
			runtime.Gosched()
			continue
		}
		r.Release(n)
		got += n
	}
	b.StopTimer()
	<-done
}

// What you have today: a fresh *Event with its params per event, through a
// buffered channel. Same fill work as BenchmarkRingValueSlots.
func BenchmarkChanAllocPerEvent(b *testing.B) {
	ch := make(chan *event.Event, 1<<12)
	go func() {
		for i := 0; i < b.N; i++ {
			ev := new(event.Event)
			ev.PID = uint32(i)
			// ev.AddUint(1, uint64(i))
			// ev.AddUint(2, 2)
			// ev.AddString(3, "value")
			ch <- ev
		}
		close(ch)
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for range ch {
	}
}

// Pointers through the generic ring: the ring itself works for *Event too, but
// every event still needs its own allocation or a pool.
func BenchmarkRingPointersAllocPerEvent(b *testing.B) {
	r := NewRing[*event.Event](1 << 12)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; {
			ev := new(event.Event)
			ev.PID = uint32(i)
			// ev.AddUint(1, uint64(i))
			// ev.AddUint(2, 2)
			// ev.AddString(3, "value")
			for !r.Offer(ev) {
				runtime.Gosched()
			}
			i++
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	buf := make([]*event.Event, 256)
	for got := 0; got < b.N; {
		n := r.Drain(buf)
		if n == 0 {
			runtime.Gosched()
			continue
		}
		got += n
	}
	b.StopTimer()
	<-done
}

// The whole pipeline: two producers, reorderer, a no-op handler chain.
func BenchmarkPipelineTwoSessions(b *testing.B) {
	cfg := DefaultConfig(2)
	cfg.RingSize = 1 << 14
	cfg.MaxPending = 1 << 14
	cfg.Slack = 0
	cfg.IdleTimeout = time.Hour
	cfg.Clock = func() int64 { return 0 }
	cfg.Classify = allState
	cfg.Shed.CriticalWait = time.Second
	var handled uint64
	cfg.Handlers = []Handler{HandlerFunc(func(*event.Event) { handled++ })}
	p, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	p.Start()

	per := b.N / 2
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	done := make(chan struct{}, 2)
	for s := 0; s < 2; s++ {
		go func(s int) {
			prod := p.Producer(s)
			for i := 0; i < per; i++ {
				ev := prod.Acquire(event.Connect)
				for ev == nil {
					runtime.Gosched()
					ev = prod.Acquire(event.Connect)
				}
				ev.Timestamp = time.Unix(0, int64(2*i+s+1))
				ev.PID = uint32(s)
				// ev.AddUint(1, uint64(i))
				// ev.AddUint(2, 2)
				// ev.AddString(3, "value")
				prod.Publish()
			}
			done <- struct{}{}
		}(s)
	}
	<-done
	<-done
	p.Close()
	b.StopTimer()
	b.ReportMetric(float64(2*per)/time.Since(start).Seconds()/1e6, "Mevents/s")
}
