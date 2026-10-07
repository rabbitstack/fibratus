package pipeline

import (
	"runtime"
	"sync"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
)

func TestRingCapacityRounding(t *testing.T) {
	for in, want := range map[int]int{0: 2, 1: 2, 2: 2, 3: 4, 1000: 1024, 1024: 1024} {
		if got := NewRing[int](in).Cap(); got != want {
			t.Errorf("NewRing(%d).Cap() = %d, want %d", in, got, want)
		}
	}
}

func TestRingFullAndEmpty(t *testing.T) {
	r := NewRing[int](4)
	if a, b := r.Claim(10); a != nil || b != nil {
		t.Fatal("empty ring returned slots")
	}
	for i := 0; i < 4; i++ {
		if !r.Offer(i) {
			t.Fatalf("offer %d failed on a ring with space", i)
		}
	}
	if r.Offer(99) || r.Slot() != nil {
		t.Fatal("full ring accepted an element")
	}
	if r.Len() != 4 {
		t.Fatalf("Len = %d", r.Len())
	}
	out := make([]int, 2)
	if n := r.Drain(out); n != 2 || out[0] != 0 || out[1] != 1 {
		t.Fatalf("Drain = %d %v", n, out)
	}
	if !r.Offer(4) || !r.Offer(5) || r.Offer(6) {
		t.Fatal("space freed by Drain was not reusable exactly once per slot")
	}
}

func TestRingClaimWrapsIntoTwoSegments(t *testing.T) {
	r := NewRing[int](8)
	for i := 0; i < 6; i++ {
		r.Offer(i)
	}
	a, b := r.Claim(100)
	r.Release(len(a) + len(b))
	for i := 6; i < 11; i++ {
		r.Offer(i)
	}
	a, b = r.Claim(100) // head=6, tail=11: slots 6,7 then 0,1,2
	if len(a) != 2 || len(b) != 3 {
		t.Fatalf("segments = %d,%d, want 2,3", len(a), len(b))
	}
	var got []int
	got = append(got, a...)
	got = append(got, b...)
	for i, v := range got {
		if v != 6+i {
			t.Fatalf("order broken: %v", got)
		}
	}
}

func TestRingClaimRespectsMax(t *testing.T) {
	r := NewRing[int](16)
	for i := 0; i < 10; i++ {
		r.Offer(i)
	}
	a, b := r.Claim(3)
	if len(a)+len(b) != 3 {
		t.Fatalf("claimed %d, want 3", len(a)+len(b))
	}
}

func TestRingSlotWithoutPublishIsReissued(t *testing.T) {
	r := NewRing[event.Event](4)
	s1 := r.Slot()
	s2 := r.Slot()
	if s1 != s2 {
		t.Fatal("unpublished slot must be handed out again")
	}
	if r.Len() != 0 {
		t.Fatal("unpublished slot leaked to the consumer")
	}
}

func TestRingDrainZeroesPointerSlots(t *testing.T) {
	r := NewRing[*event.Event](8)
	evs := []*event.Event{{PID: 1}, {PID: 2}, {PID: 3}}
	for _, e := range evs {
		r.Offer(e)
	}
	out := make([]*event.Event, 8)
	n := r.Drain(out)
	if n != 3 || out[0] != evs[0] || out[2] != evs[2] {
		t.Fatalf("Drain returned %d, %v", n, out[:n])
	}
	for i, p := range r.buf {
		if p != nil {
			t.Fatalf("slot %d still pins an event after Drain", i)
		}
	}
}

func TestRingConcurrentOfferDrain(t *testing.T) {
	const n = 300_000
	r := NewRing[uint64](1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint64(0); i < n; {
			if r.Offer(i) {
				i++
			} else {
				runtime.Gosched()
			}
		}
	}()
	buf := make([]uint64, 64)
	var next uint64
	for next < n {
		k := r.Drain(buf)
		if k == 0 {
			runtime.Gosched()
			continue
		}
		for _, v := range buf[:k] {
			if v != next {
				t.Fatalf("got %d, want %d", v, next)
			}
			next++
		}
	}
	wg.Wait()
}

// The zero-copy path: the producer fills slots in place, the consumer reads
// them in place, and nothing is ever copied or allocated per event.
func TestRingConcurrentValueSlots(t *testing.T) {
	const n = 100_000
	r := NewRing[event.Event](256) // small ring: forces many wrap-arounds
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; {
			s := r.Slot()
			if s == nil {
				runtime.Gosched()
				continue
			}
			s.Reset()
			s.PID = uint32(i)
			//s.AddUint(1, uint64(i))
			//s.AddString(2, "x")
			r.Publish()
			i++
		}
	}()
	next := 0
	for next < n {
		a, b := r.Claim(32)
		cnt := len(a) + len(b)
		if cnt == 0 {
			runtime.Gosched()
			continue
		}
		for _, seg := range [][]event.Event{a, b} {
			for i := range seg {
				ev := &seg[i]
				if int(ev.PID) != next {
					t.Fatalf("PID = %d, want %d", ev.PID, next)
				}
				// if p := ev.Param(1); p == nil || p.U != uint64(next) {
				// 	t.Fatalf("param lost at %d", next)
				// }
				next++
			}
		}
		r.Release(cnt)
	}
	wg.Wait()
}
