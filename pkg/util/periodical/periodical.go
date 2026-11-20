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

// Package periodical provides a clock and a periodic trigger driven by event
// time instead of wall-clock time.
//
// Driving housekeeping from event time keeps it consistent with the data
// being processed: it advances as fast as the events do, stands still when
// no events flow, and is not skewed by replays or by delays between the
// kernel stamping an event and the process receiving it.
package periodical

import "time"

// Periodic is the contract for all implementers interested in executing
// a periodic task. The trigger interval is driver by the timestamp obtained
// from the event iself.
type Periodic interface {
	RunPeriodic(ts int64)
}

// Periodical is a monotonic event-time clock with a periodic trigger.
//
// The clock only moves forward. A late event carrying an older timestamp
// never rewinds it, and a single event from the far future moves it once and
// for all, expiring everything older, but never expires newer data.
//
// The trigger fires when the clock has advanced by at least the interval
// since it last fired. The very first trigger fires as soon as any time has
// been observed, which is harmless for housekeeping because there is
// nothing to clean up yet.
//
// Periodical is not safe for concurrent use. The caller serializes access,
// typically with the mutex that already guards the state being maintained.
type Periodical struct {
	interval int64  // trigger period in ns
	clock    int64  // newest event time seen, ns since the Unix epoch
	last     int64  // clock value when the trigger last fired
	fired    bool   // whether the trigger has ever fired
	fn       func() // closure bound by NewFunc, run by Observe
}

// New creates a periodic trigger that fires every interval of event time.
// A zero or negative interval fires on every tick.
func New(interval time.Duration) *Periodical {
	return &Periodical{interval: int64(interval)}
}

// Interval returns the trigger period.
func (p *Periodical) Interval() time.Duration { return time.Duration(p.interval) }

// Advance moves the clock forward to the nanoseconds timestamp if it is newer
// than the current time and returns the clock reading in nanoseconds since the
// Unix epoch.
func (p *Periodical) Advance(ts int64) int64 {
	if ts > p.clock {
		p.clock = ts
	}
	return p.clock
}

// Clock returns the clock reading in nanoseconds since the Unix epoch. It is
// zero until the first timestamp is observed.
func (p *Periodical) Clock() int64 { return p.clock }

// Due reports whether the interval has elapsed since the trigger last fired,
// without advancing the clock or consuming the trigger. It is always false
// before any time has been observed.
func (p *Periodical) Due() bool {
	if p.clock == 0 {
		return false
	}
	return !p.fired || p.clock-p.last >= p.interval
}

// Mark records that the periodic work has just been performed so the next
// period starts from the current clock reading.
func (p *Periodical) Mark() {
	p.last = p.clock
	p.fired = true
}

// Tick advances the clock to ts and reports whether the periodic work is due.
// When it returns true the trigger is consumed and the next period starts.
func (p *Periodical) Tick(ts int64) bool {
	return p.TickOr(ts, false)
}

// TickOr is like Tick, but also fires when force is true. It serves callers
// that must run the work early, for instance because a buffer filled up, and
// still want the period restarted so the work isn't repeated needlessly.
func (p *Periodical) TickOr(ts int64, force bool) bool {
	p.Advance(ts)
	if force || p.Due() {
		p.Mark()
		return true
	}
	return false
}

// Do advances the clock to ts and runs fn if the interval has elapsed since
// the last run. It reports whether fn ran. A nil fn still consumes the trigger.
func (p *Periodical) Do(ts int64, fn func()) bool {
	return p.DoOr(ts, false, fn)
}

// DoOr is like Do, but also runs fn when force is true, restarting the period.
func (p *Periodical) DoOr(ts int64, force bool, fn func()) bool {
	if !p.TickOr(ts, force) {
		return false
	}
	if fn != nil {
		fn()
	}
	return true
}

// NewFunc creates a periodic trigger with a closure bound to it. Feed it event
// timestamps with Observe and fn runs once per interval of event time.
func NewFunc(interval time.Duration, fn func()) *Periodical {
	return &Periodical{interval: int64(interval), fn: fn}
}

// Observe advances the clock to ts and runs the closure bound with NewFunc if
// the interval has elapsed. It reports whether the closure ran, and does
// nothing but advance the clock when no closure is bound.
func (p *Periodical) Observe(ts int64) bool {
	return p.Do(ts, p.fn)
}

// Age returns how much event time has elapsed since the timestamp.
// Timestamps in the future of the clock have zero age.
func (p *Periodical) Age(ts int64) time.Duration {
	if d := p.clock - ts; d > 0 {
		return time.Duration(d)
	}
	return 0
}

// Expired reports whether the timestamp is at least ttl older than
// the clock.
func (p *Periodical) Expired(ts int64, ttl time.Duration) bool {
	return p.clock > ts && p.clock-ts >= int64(ttl)
}

// Reset returns the clock and the trigger to their initial state, keeping the
// interval.
func (p *Periodical) Reset() {
	p.clock, p.last, p.fired = 0, 0, false
}
