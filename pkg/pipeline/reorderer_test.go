package pipeline

import (
	"slices"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

func evAt(ts int64) *event.Event { return &event.Event{Timestamp: time.Unix(0, ts)} }

func release(r *Reorderer, now int64) []int64 {
	var out []int64
	wm, ok := r.Watermark(now)
	for {
		ev, more := r.Next(wm, ok)
		if !more {
			return out
		}
		out = append(out, ev.Timestamp.UnixNano())
	}
}

func TestReorderMergesTwoSessions(t *testing.T) {
	r := NewReorderer(2, 0, 1<<60, 1<<10, 0)

	// Session 0 runs ahead; session 1 hasn't spoken yet, so nothing may leave.
	for _, ts := range []int64{1, 3, 5} {
		r.Add(0, evAt(ts), 0)
	}
	if got := release(r, 0); len(got) != 0 {
		t.Fatalf("released %v before session 1 reported", got)
	}

	// Session 1 reports ts=2: the watermark becomes min(5,2)=2.
	r.Add(1, evAt(2), 0)
	if got := release(r, 0); !slices.Equal(got, []int64{1, 2}) {
		t.Fatalf("released %v, want [1 2]", got)
	}

	r.Add(1, evAt(4), 0)
	r.Add(1, evAt(6), 0)
	if got := release(r, 0); !slices.Equal(got, []int64{3, 4, 5}) {
		t.Fatalf("released %v, want [3 4 5]", got)
	}

	// 6 stays until session 0 moves past it; the final flush releases it.
	ev, ok := r.Next(1<<62, true)
	if !ok || ev.Timestamp.UnixNano() != 6 {
		t.Fatalf("flush = %v %v", ev, ok)
	}
	if s := r.Stats(); s.Late != 0 || s.Forced != 0 || s.Emitted != 6 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestReorderSlackHoldsBackRecentEvents(t *testing.T) {
	r := NewReorderer(1, 10, 1<<60, 1<<10, 0)
	r.Add(0, evAt(100), 0)
	r.Add(0, evAt(105), 0)
	if got := release(r, 0); len(got) != 0 {
		t.Fatalf("released %v inside the slack window", got)
	}
	r.Add(0, evAt(111), 0) // watermark = 111-10 = 101
	if got := release(r, 0); !slices.Equal(got, []int64{100}) {
		t.Fatalf("released %v, want [100]", got)
	}
	// A straggler within the slack is still ordered correctly.
	r.Add(0, evAt(102), 0)
	r.Add(0, evAt(120), 0) // watermark = 110
	if got := release(r, 0); !slices.Equal(got, []int64{102, 105}) {
		t.Fatalf("released %v, want [102 105]", got)
	}
}

func TestReorderIdleSessionDoesNotFreezeWatermark(t *testing.T) {
	r := NewReorderer(2, 0, 10, 1<<10, 0)
	r.Add(0, evAt(5), 18)
	r.Add(0, evAt(7), 18)

	// At now=20 session 1 has been silent for 20 >= 10 and session 0 has not.
	if got := release(r, 20); !slices.Equal(got, []int64{5, 7}) {
		t.Fatalf("released %v, want [5 7]", got)
	}

	// Before the idle timeout the silent session still holds the watermark.
	r2 := NewReorderer(2, 0, 10, 1<<10, 0)
	r2.Add(0, evAt(5), 4)
	if got := release(r2, 5); len(got) != 0 {
		t.Fatalf("released %v before the idle timeout", got)
	}
}

func TestReorderCountsLateEvents(t *testing.T) {
	r := NewReorderer(1, 0, 1<<60, 1<<10, 0)
	r.Add(0, evAt(10), 0)
	r.Add(0, evAt(20), 0)
	release(r, 0) // releases 10 (watermark 20 releases both actually)
	r.Add(0, evAt(4), 0)
	got := release(r, 0)
	if !slices.Equal(got, []int64{4}) {
		t.Fatalf("late event released as %v", got)
	}
	if s := r.Stats(); s.Late != 1 {
		t.Fatalf("Late = %d, want 1", s.Late)
	}
}

func TestReorderForcesReleaseWhenFull(t *testing.T) {
	r := NewReorderer(2, 0, 1<<60, 3, 0)
	for _, ts := range []int64{30, 10, 20} { // session 1 never reports
		r.Add(0, evAt(ts), 0)
	}
	got := release(r, 0)
	if !slices.Equal(got, []int64{10}) {
		t.Fatalf("released %v, want the oldest only", got)
	}
	if s := r.Stats(); s.Forced != 1 {
		t.Fatalf("Forced = %d, want 1", s.Forced)
	}
}

func TestReorderStableForEqualTimestamps(t *testing.T) {
	r := NewReorderer(1, 0, 1<<60, 1<<10, 0)
	var evs []*event.Event
	for i := 0; i < 5; i++ {
		e := evAt(50)
		e.PID = uint32(i)
		evs = append(evs, e)
		r.Add(0, e, 0)
	}
	for i := 0; i < 5; i++ {
		got, ok := r.Next(1<<62, true)
		if !ok || got != evs[i] {
			t.Fatalf("arrival order not preserved at %d", i)
		}
	}
}

func TestHeapOrdersRandomInput(t *testing.T) {
	var h eventHeap
	in := []int64{9, 3, 7, 1, 8, 2, 5, 4, 6, 0, 3, 3}
	for i, k := range in {
		h.push(entry{key: k, n: uint64(i)})
	}
	var out []int64
	for len(h) > 0 {
		out = append(out, h.pop().key)
	}
	if !slices.IsSorted(out) || len(out) != len(in) {
		t.Fatalf("heap output %v", out)
	}
}
