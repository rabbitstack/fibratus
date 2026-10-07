package pipeline

import (
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
)

func tp(c ShedClass) event.Type { return event.Type(byte(c)) }

func classByFirstByte(t event.Type) ShedClass { return ShedClass(t) }

func shedCfg() ShedConfig {
	c := DefaultShedConfig()
	c.SampleEvery = 1 // sample on every call so the thresholds are exact in tests
	c.CriticalWait = 0
	return c
}

func newTestProducer(t *testing.T, size int, cfg ShedConfig) (*Ring[event.Event], *Producer) {
	t.Helper()
	r := NewRing[event.Event](size)
	p, err := NewProducer(r, classByFirstByte, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r, p
}

func push(p *Producer, c ShedClass) bool {
	ev := p.Acquire(tp(c))
	if ev == nil {
		return false
	}
	ev.PID = 1
	p.Publish()
	return true
}

// consumerLeaves simulates the consumer releasing slots until `keep` remain.
func consumerLeaves(r *Ring[event.Event], keep int) {
	a, b := r.Claim(1 << 20)
	r.Release(len(a) + len(b) - keep)
}

func TestSheddingTiersAndHysteresis(t *testing.T) {
	const size = 1024 // thresholds: enter1=716 exit1=512 enter2=921 exit2=768 reserve=64
	r, p := newTestProducer(t, size, shedCfg())

	// Level 1 kicks in at 70%: noisy events stop being admitted.
	accepted := 0
	for i := 0; i < size; i++ {
		if push(p, ClassNoisy) {
			accepted++
		}
	}
	if accepted != 716 {
		t.Fatalf("noisy accepted = %d, want 716", accepted)
	}
	if p.Stats().ShedLevel != 1 {
		t.Fatalf("level = %d, want 1", p.Stats().ShedLevel)
	}

	// Normal events still flow at level 1 until level 2 at 90%.
	accepted = 0
	for push(p, ClassNormal) {
		accepted++
	}
	if accepted != 921-716 {
		t.Fatalf("normal accepted = %d, want %d", accepted, 921-716)
	}
	if p.Stats().ShedLevel != 2 {
		t.Fatalf("level = %d, want 2", p.Stats().ShedLevel)
	}

	// State events are never shed by the level: they use the remaining space
	// and are only lost when the ring is completely full.
	accepted = 0
	for push(p, ClassState) {
		accepted++
	}
	if accepted != size-921 {
		t.Fatalf("state accepted = %d, want %d", accepted, size-921)
	}
	st := p.Stats()
	if st.DroppedState != 1 {
		t.Fatalf("DroppedState = %d, want exactly the one that hit a full ring", st.DroppedState)
	}
	if st.DroppedNoisy == 0 || st.DroppedNormal == 0 {
		t.Fatalf("shed counters not updated: %+v", st)
	}

	// Hysteresis: at 600 the level drops to 1 (below exit2=768) but not to 0
	// (exit1=512), so noisy is still shed while normal flows again.
	consumerLeaves(r, 600)
	if push(p, ClassNoisy) {
		t.Fatal("noisy admitted at level 1")
	}
	if p.Stats().ShedLevel != 1 {
		t.Fatalf("level = %d, want 1", p.Stats().ShedLevel)
	}
	if !push(p, ClassNormal) {
		t.Fatal("normal shed at level 1")
	}

	// Below exit1 everything flows again.
	consumerLeaves(r, 400)
	if !push(p, ClassNoisy) {
		t.Fatal("noisy still shed after the ring drained")
	}
	if p.Stats().ShedLevel != 0 {
		t.Fatalf("level = %d, want 0", p.Stats().ShedLevel)
	}
	if p.Stats().Transitions < 4 {
		t.Fatalf("transitions = %d, want at least 0->1->2->1->0", p.Stats().Transitions)
	}
}

func TestReserveIsKeptForState(t *testing.T) {
	cfg := shedCfg()
	cfg.Enter1, cfg.Enter2 = 0.97, 0.99 // park the tiers out of the way
	cfg.Exit1, cfg.Exit2 = 0.50, 0.60
	cfg.ReserveFrac = 4.0 / 64
	_, p := newTestProducer(t, 64, cfg)

	normal := 0
	for push(p, ClassNormal) {
		normal++
	}
	if normal != 60 {
		t.Fatalf("normal accepted = %d, want 60 (64 minus the 4-slot reserve)", normal)
	}
	state := 0
	for push(p, ClassState) {
		state++
	}
	if state != 4 {
		t.Fatalf("state accepted = %d, want the 4 reserved slots", state)
	}
}

func TestCriticalWaitSucceedsWhenConsumerCatchesUp(t *testing.T) {
	cfg := shedCfg()
	cfg.CriticalWait = 2 * time.Second
	r, p := newTestProducer(t, 8, cfg)
	for push(p, ClassState) {
		if r.Len() == 8 {
			break
		}
	}
	go func() {
		time.Sleep(5 * time.Millisecond)
		a, b := r.Claim(8)
		r.Release(len(a) + len(b))
	}()
	if !push(p, ClassState) {
		t.Fatal("state event lost although the consumer freed space within CriticalWait")
	}
	if got := p.Stats().DroppedState; got != 0 {
		t.Fatalf("DroppedState = %d, want 0", got)
	}
}

func TestCriticalWaitIsBounded(t *testing.T) {
	cfg := shedCfg()
	cfg.CriticalWait = 20 * time.Millisecond
	_, p := newTestProducer(t, 4, cfg)
	for i := 0; i < 4; i++ {
		push(p, ClassState)
	}
	start := time.Now()
	if push(p, ClassState) {
		t.Fatal("accepted into a full ring")
	}
	if d := time.Since(start); d < 15*time.Millisecond || d > time.Second {
		t.Fatalf("waited %v, want about 20ms", d)
	}
	if p.Stats().DroppedState != 1 {
		t.Fatal("lost state event was not counted")
	}
}

func TestAcquireReturnsResetSlot(t *testing.T) {
	r, p := newTestProducer(t, 4, shedCfg())
	for i := 0; i < 4; i++ {
		ev := p.Acquire(tp(ClassState))
		ev.PID = 77
		//ev.AddUint(1, 1)
		p.Publish()
	}
	consumerLeaves(r, 0) // consumer released without cleaning the slots
	ev := p.Acquire(tp(ClassState))
	if ev == nil || ev.PID != 0 || len(ev.Params) != 0 {
		t.Fatalf("Acquire returned a dirty slot: %+v", ev)
	}
}

func TestUnknownClassIsTreatedAsNoisy(t *testing.T) {
	_, p := newTestProducer(t, 64, shedCfg())
	ev := p.Acquire(event.RegOpenKey)
	if ev == nil {
		t.Fatal("shed at level 0")
	}
	p.Publish()
}

func TestShedConfigValidation(t *testing.T) {
	bad := []func(*ShedConfig){
		func(c *ShedConfig) { c.SampleEvery = 0 },
		func(c *ShedConfig) { c.Enter1, c.Exit1 = 0.4, 0.5 },
		func(c *ShedConfig) { c.Enter2 = 1.5 },
		func(c *ShedConfig) { c.Exit2 = 0.95 },
		func(c *ShedConfig) { c.ReserveFrac = 0.9 },
		func(c *ShedConfig) { c.CriticalWait = -1 },
	}
	for i, mut := range bad {
		c := DefaultShedConfig()
		mut(&c)
		if _, err := NewProducer(NewRing[event.Event](16), nil, c); err == nil {
			t.Errorf("case %d: invalid config accepted", i)
		}
	}
}
