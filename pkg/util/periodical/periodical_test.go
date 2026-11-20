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

package periodical

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// base is a realistic event time: 2026-10-20 12:00:00 UTC.
var base = time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)

// at returns the FILETIME timestamp d after base.
func at(d time.Duration) int64 { return base.Add(d).UnixNano() }

func TestNewAndInterval(t *testing.T) {
	p := New(time.Second)
	assert.Equal(t, time.Second, p.Interval())
	assert.Zero(t, p.Clock(), "the clock is unset until the first timestamp")
	assert.False(t, p.Due())
}

func TestAdvanceIsMonotonic(t *testing.T) {
	p := New(time.Second)

	assert.Equal(t, base.UnixNano(), p.Advance(at(0)))
	assert.Equal(t, base.Add(5*time.Second).UnixNano(), p.Advance(at(5*time.Second)))

	// a late event with an older timestamp must not rewind the clock
	assert.Equal(t, base.Add(5*time.Second).UnixNano(), p.Advance(at(time.Second)))
	assert.Equal(t, base.Add(5*time.Second).UnixNano(), p.Clock())

	// equal timestamps are a no-op
	assert.Equal(t, base.Add(5*time.Second).UnixNano(), p.Advance(at(5*time.Second)))
}

func TestAdvanceRandomOrderNeverMovesBackwards(t *testing.T) {
	p := New(time.Second)
	rng := rand.New(rand.NewSource(42))

	var max int64
	for i := 0; i < 10_000; i++ {
		ts := at(time.Duration(rng.Int63n(int64(time.Hour))))
		if ts > max {
			max = ts
		}
		prev := p.Clock()
		got := p.Advance(ts)

		assert.GreaterOrEqual(t, got, prev, "clock moved backwards")
		assert.Equal(t, max, got)
	}
}

func TestDueIsFalseBeforeAnyTimeIsObserved(t *testing.T) {
	p := New(time.Second)
	assert.False(t, p.Due())
	assert.False(t, p.Due(), "Due never consumes the trigger")
}

func TestDueDoesNotConsumeTheTrigger(t *testing.T) {
	p := New(time.Second)
	p.Advance(at(0))

	assert.True(t, p.Due())
	assert.True(t, p.Due(), "stays due until Mark")

	p.Mark()
	assert.False(t, p.Due())
}

func TestTickFiresOnFirstTimestamp(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Tick(at(0)), "the first observation fires")
	assert.False(t, p.Tick(at(0)), "and then it waits a full period")
}

func TestTickFiresEveryInterval(t *testing.T) {
	p := New(time.Second)

	assert.True(t, p.Tick(at(0)))
	assert.False(t, p.Tick(at(999*time.Millisecond)), "just under the interval")
	assert.True(t, p.Tick(at(time.Second)), "exactly one interval after the last firing")
	assert.False(t, p.Tick(at(1999*time.Millisecond)))
	assert.True(t, p.Tick(at(2*time.Second)))
}

func TestTickPeriodRestartsFromTheFiringTime(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Tick(at(0)))

	// a long gap fires once, not once per missed period
	assert.True(t, p.Tick(at(10*time.Second)))
	assert.False(t, p.Tick(at(10*time.Second+500*time.Millisecond)))
	assert.True(t, p.Tick(at(11*time.Second)))
}

func TestTickIgnoresLateEvents(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Tick(at(5*time.Second)))

	// older events neither rewind the clock nor fire the trigger
	for i := 0; i < 5; i++ {
		assert.False(t, p.Tick(at(time.Duration(i)*time.Second)))
	}
	assert.Equal(t, base.Add(5*time.Second).UnixNano(), p.Clock())
	assert.True(t, p.Tick(at(6*time.Second)))
}

func TestTickOrForceFiresEarlyAndRestartsThePeriod(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Tick(at(0)))

	assert.True(t, p.TickOr(at(100*time.Millisecond), true), "forced before the interval")
	// the period restarted at +100ms, so +1s is no longer due...
	assert.False(t, p.Tick(at(time.Second)))
	// ...but +1.1s is
	assert.True(t, p.Tick(at(1100*time.Millisecond)))
}

func TestTickOrWithoutForceBehavesLikeTick(t *testing.T) {
	a, b := New(time.Second), New(time.Second)
	for _, d := range []time.Duration{0, 400 * time.Millisecond, time.Second, 1500 * time.Millisecond, 2 * time.Second} {
		assert.Equal(t, a.Tick(at(d)), b.TickOr(at(d), false), "offset %v", d)
	}
}

func TestTickOrForceStillAdvancesTheClock(t *testing.T) {
	p := New(time.Hour)
	assert.True(t, p.TickOr(at(3*time.Second), true))
	assert.Equal(t, base.Add(3*time.Second).UnixNano(), p.Clock())
}

func TestZeroIntervalFiresOnEveryTick(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		p := New(interval)
		assert.True(t, p.Tick(at(0)))
		assert.True(t, p.Tick(at(0)), "interval %v", interval)
		assert.True(t, p.Tick(at(time.Millisecond)))
	}
}

func TestMarkRestartsThePeriod(t *testing.T) {
	p := New(time.Second)
	p.Advance(at(0))
	p.Mark()

	p.Advance(at(999 * time.Millisecond))
	assert.False(t, p.Due())

	p.Advance(at(time.Second))
	assert.True(t, p.Due())
}

func TestAge(t *testing.T) {
	p := New(time.Second)
	p.Advance(at(10 * time.Second))

	assert.Equal(t, 10*time.Second, p.Age(at(0)))
	assert.Equal(t, 4*time.Second, p.Age(at(6*time.Second)))
	assert.Zero(t, p.Age(at(10*time.Second)), "an entry stamped now has no age")
	assert.Zero(t, p.Age(at(20*time.Second)), "future timestamps have no age")
}

func TestExpired(t *testing.T) {
	p := New(time.Second)
	p.Advance(at(10 * time.Second))

	ttl := 5 * time.Second
	assert.True(t, p.Expired(at(0), ttl))
	assert.True(t, p.Expired(at(5*time.Second), ttl), "age equal to the ttl expires")
	assert.False(t, p.Expired(at(5*time.Second+time.Millisecond), ttl), "just younger than the ttl")
	assert.False(t, p.Expired(at(10*time.Second), ttl))
	assert.False(t, p.Expired(at(20*time.Second), ttl), "future timestamps never expire")
}

func TestExpiredWithUnsetClock(t *testing.T) {
	p := New(time.Second)
	assert.False(t, p.Expired(at(0), time.Second), "nothing expires before time is observed")
}

// One event from a different clock base moves the clock once and expires
// everything older, but never the events at or after it.
func TestFarFutureTimestamp(t *testing.T) {
	p := New(time.Second)
	p.Advance(at(0))

	future := at(24 * time.Hour)
	p.Advance(future)

	assert.True(t, p.Expired(at(0), time.Minute))
	assert.False(t, p.Expired(future, time.Minute))
	assert.Equal(t, 24*time.Hour, p.Age(at(0)))
}

func TestReset(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Tick(at(0)))
	assert.False(t, p.Tick(at(100*time.Millisecond)))

	p.Reset()

	assert.Zero(t, p.Clock())
	assert.False(t, p.Due())
	assert.Equal(t, time.Second, p.Interval(), "the interval survives a reset")
	assert.True(t, p.Tick(at(200*time.Millisecond)), "fires again like a fresh instance")
}

// Typical use: sweep the pending map at most once per interval of event time.
func TestSweepScenario(t *testing.T) {
	p := New(time.Second)
	pending := map[int]int64{} // id -> nanoseconds
	const ttl = 5 * time.Second

	sweeps := 0
	enqueue := func(id int, ts int64) {
		if p.Tick(ts) {
			sweeps++
			for id, enq := range pending {
				if p.Expired(enq, ttl) {
					delete(pending, id)
				}
			}
		}
		pending[id] = ts
	}

	enqueue(1, at(0))
	enqueue(2, at(2*time.Second))
	enqueue(3, at(4*time.Second))
	assert.Len(t, pending, 3, "nothing is older than the ttl yet")

	enqueue(4, at(6*time.Second)) // sweeps: 1 is 6s old
	assert.NotContains(t, pending, 1)
	assert.Contains(t, pending, 2)

	enqueue(5, at(6*time.Second+300*time.Millisecond)) // within the period, no sweep
	before := sweeps
	enqueue(6, at(6*time.Second+600*time.Millisecond))
	assert.Equal(t, before, sweeps, "sweeps are throttled to one per interval")

	enqueue(7, at(20*time.Second)) // everything else is stale
	assert.Equal(t, []int{7}, keys(pending))
}

func keys(m map[int]int64) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func BenchmarkTick(b *testing.B) {
	p := New(time.Second)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Tick(at(time.Duration(i) * time.Millisecond))
	}
}

func TestDoRunsClosureOncePerInterval(t *testing.T) {
	p := New(time.Second)
	runs := 0
	fn := func() { runs++ }

	assert.True(t, p.Do(at(0), fn), "the first observation runs it")
	assert.False(t, p.Do(at(500*time.Millisecond), fn))
	assert.Equal(t, 1, runs)

	assert.True(t, p.Do(at(time.Second), fn))
	assert.True(t, p.Do(at(2*time.Second), fn))
	assert.Equal(t, 3, runs)
}

func TestDoIgnoresLateEvents(t *testing.T) {
	p := New(time.Second)
	runs := 0
	p.Do(at(5*time.Second), func() { runs++ })

	for i := 0; i < 5; i++ {
		assert.False(t, p.Do(at(time.Duration(i)*time.Second), func() { runs++ }))
	}
	assert.Equal(t, 1, runs)
}

func TestDoNilClosureStillConsumesTheTrigger(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Do(at(0), nil))
	assert.False(t, p.Do(at(100*time.Millisecond), nil))
}

func TestDoOrForceRunsEarlyAndRestartsThePeriod(t *testing.T) {
	p := New(time.Second)
	runs := 0
	fn := func() { runs++ }
	p.Do(at(0), fn)

	assert.True(t, p.DoOr(at(100*time.Millisecond), true, fn))
	assert.False(t, p.Do(at(time.Second), fn), "the period restarted at +100ms")
	assert.True(t, p.Do(at(1100*time.Millisecond), fn))
	assert.Equal(t, 3, runs)
}

func TestDoReentrantClosureDoesNotRecurse(t *testing.T) {
	p := New(time.Second)
	runs := 0
	var fn func()
	fn = func() {
		runs++
		// the trigger was consumed before the closure ran
		p.Do(at(0), fn)
	}

	assert.True(t, p.Do(at(0), fn))
	assert.Equal(t, 1, runs)
}

func TestDoPanickingClosureConsumesTheTrigger(t *testing.T) {
	p := New(time.Second)

	assert.Panics(t, func() { p.Do(at(0), func() { panic("boom") }) })

	runs := 0
	assert.False(t, p.Do(at(100*time.Millisecond), func() { runs++ }),
		"a panic must not leave the period unconsumed and retrigger on every event")
	assert.Zero(t, runs)
}

func TestObserveRunsTheBoundClosure(t *testing.T) {
	runs := 0
	p := NewFunc(time.Second, func() { runs++ })

	assert.True(t, p.Observe(at(0)))
	assert.False(t, p.Observe(at(999*time.Millisecond)))
	assert.True(t, p.Observe(at(time.Second)))
	assert.Equal(t, 2, runs)
	assert.Equal(t, time.Second, p.Interval())
}

func TestObserveWithoutBoundClosure(t *testing.T) {
	p := New(time.Second)
	assert.True(t, p.Observe(at(0)), "the trigger fires but has nothing to run")
	assert.Equal(t, base.UnixNano(), p.Clock())

	q := NewFunc(time.Second, nil)
	assert.NotPanics(t, func() { q.Observe(at(0)) })
}

func TestResetKeepsTheBoundClosure(t *testing.T) {
	runs := 0
	p := NewFunc(time.Second, func() { runs++ })
	p.Observe(at(0))
	p.Reset()

	assert.True(t, p.Observe(at(0)))
	assert.Equal(t, 2, runs)
}

func TestDoClosureSeesTheAdvancedClock(t *testing.T) {
	p := New(time.Second)
	var seen int64
	p.Do(at(7*time.Second), func() { seen = p.Clock() })
	assert.Equal(t, base.Add(7*time.Second).UnixNano(), seen)
}
