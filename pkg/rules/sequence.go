/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package rules

import (
	"context"
	"expvar"
	fsm "github.com/qmuntal/stateless"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/atomic"
	log "github.com/sirupsen/logrus"
	"sort"
	"sync"
	"time"
)

const (
	// maxOutstandingPartials determines the maximum number of partials per sequence index
	maxOutstandingPartials = 1000
)

var (
	partialsPerSequence   = expvar.NewMap("sequence.partials.count")
	partialExpirations    = expvar.NewMap("sequence.partial.expirations")
	partialBreaches       = expvar.NewMap("sequence.partial.breaches")
	matchTransitionErrors = expvar.NewInt("sequence.match.transition.errors")

	// maxSequencePartialLifetime indicates the maximum time for the
	// partial to exist in the sequence state. If the partial has been
	// placed in the sequence state more than allowed, it is removed
	maxSequencePartialLifetime = time.Hour * 4
)

var (
	// sequenceTerminalState represents the final state in the FSM.
	// This state is transitioned when the last rule in the sequence
	// produces a match
	sequenceTerminalState = fsm.State("terminal")
	// sequenceDeadlineState represents the state to which other
	// states transition if the rule's max span is reached
	sequenceDeadlineState = fsm.State("deadline")
	// sequenceExpiredState designates the state to which other
	// states transition when the sequence is expired
	sequenceExpiredState = fsm.State("expired")
	// sequenceInitialState represents the initial sequence state
	sequenceInitialState = fsm.State(0)

	// transitions for match, cancel, reset, and expire triggers
	matchTransition  = fsm.Trigger("match")
	cancelTransition = fsm.Trigger("cancel")
	resetTransition  = fsm.Trigger("reset")
	expireTransition = fsm.Trigger("expire")
)

// sequenceState represents the state of the
// ordered sequence of multiple events that
// may have time-frame constraints. A deterministic
// finite state machine tracks the matching status of
// each expression (state) in the machine.
type sequenceState struct {
	filter  filter.Filter
	seq     *ql.Sequence
	name    string
	maxSpan time.Duration

	// partials keeps the state of all matched events per expression
	partials map[int][]*kevent.Kevent
	// mu guards the partials map
	mu sync.RWMutex

	// matches stores only the event that matched
	// the upstream partials. These events will
	// be propagated in the rule action context
	matches map[int]*kevent.Kevent
	// mmu guards the matches map
	mmu sync.RWMutex

	fsm *fsm.StateMachine

	// exprs stores the expression index to
	// its respective string representation
	exprs              map[int]string
	spanDeadlines      map[fsm.State]*time.Timer
	inDeadline         atomic.Bool
	inExpired          atomic.Bool
	initialState       fsm.State
	isPartialsBreached atomic.Bool

	// states keeps the mapping between expression
	// index and its matching state. Whenever the expression
	// evaluates to true the state is updated for the index
	// pertaining to the expression sequence slot
	states map[fsm.State]bool
	// smu guards the states map
	smu sync.RWMutex
}

func newSequenceState(f filter.Filter, c *config.FilterConfig) *sequenceState {
	ss := &sequenceState{
		filter:        f,
		seq:           f.GetSequence(),
		name:          c.Name,
		maxSpan:       f.GetSequence().MaxSpan,
		partials:      make(map[int][]*kevent.Kevent),
		states:        make(map[fsm.State]bool),
		matches:       make(map[int]*kevent.Kevent),
		exprs:         make(map[int]string),
		spanDeadlines: make(map[fsm.State]*time.Timer),
		initialState:  sequenceInitialState,
		inDeadline:    atomic.MakeBool(false),
	}

	ss.initFSM()

	ss.configureFSM()

	return ss
}

func (s *sequenceState) events() []*kevent.Kevent {
	s.mmu.RLock()
	defer s.mmu.RUnlock()
	events := make([]*kevent.Kevent, 0, len(s.matches))
	for _, e := range s.matches {
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	return events
}

func (s *sequenceState) isStateSchedulable(state fsm.State) bool {
	return state != s.initialState && state != sequenceTerminalState && state != sequenceExpiredState && state != sequenceDeadlineState
}

// initFSM initializes the state machine and installs transition callbacks
// that are triggered when the expression in the sequence matches, it expires
// or the deadline occurs.
func (s *sequenceState) initFSM() {
	s.fsm = fsm.NewStateMachine(s.initialState)
	s.fsm.OnTransitioned(func(ctx context.Context, transition fsm.Transition) {
		// schedule span deadline for the current state unless initial/meta states
		if s.maxSpan != 0 && s.isStateSchedulable(s.currentState()) {
			log.Debugf("scheduling max span deadline of %v for expression [%s] of sequence [%s]", s.maxSpan, s.expr(s.currentState()), s.name)
			s.scheduleMaxSpanDeadline(s.currentState(), s.maxSpan)
		}
		// if the sequence was deadlined/expired, we can disable the deadline
		// status when the first expression in the sequence is reevaluated
		if transition.Source == s.initialState && s.inDeadline.Load() {
			s.inDeadline.Store(false)
		}
		if transition.Source == s.initialState && s.inExpired.Load() {
			s.inExpired.Store(false)
		}
		// clear state in case of expire/deadline transitions
		if transition.Trigger == expireTransition || transition.Trigger == cancelTransition {
			s.clear()
		}
		if transition.Trigger == matchTransition {
			log.Debugf("state trigger from expression [%s] of sequence [%s]", s.expr(transition.Source), s.name)
			// a match occurred from current to next state.
			// Stop deadline execution for the old current state
			if span, ok := s.spanDeadlines[transition.Source]; ok {
				log.Debugf("stopped max span deadline for expression [%s] of sequence [%s]", s.expr(transition.Source), s.name)
				span.Stop()
				delete(s.spanDeadlines, transition.Source)
			}
			// save expression match
			s.states[transition.Source] = true
		}
	})
}

// configureFSM sets up the states and transitions of the state automata.
// A simplified representation of the constructed automata is better
// visualized in the diagram above
//
//	       +-----+        +-----+        +-----+
//	---->  |  0  | -----> |  1  | -----> |  2  | -----> terminal
//	+      +-----+        +-----+        +-----+
//	+        |               |               |
//	+   +----+----+     +----+----+     +----+----+
//	+   |         |     |         |     |         |
//	+   v         v     v         v     v         v
//	+---------+ +---------+ +---------+ +---------+ +---------+ +---------+
//
// | deadline| | expired | | deadline| | expired | | deadline| | expired |
// +---------+ +---------+ +---------+ +---------+ +---------+ +---------+
//
// The diagram is based on the assumption that there are three expressions
// inside the sequence. In the course of normal circumstances, the initial
// state transitions to the state 1 and the state 1 to the state 2 whenever
// the expression associated to the state is evaluated to true.
// Once the final state is reached, it transitions to the terminal state and
// the sequence is considered to yield a match.
//
// However, it can happen that the maximum time span defined in the sequence
// elapses. In this situation, the sequence is promoted to the deadline state
// and the state machine is reset to the initial state. The similar behaviour
// occurs when the process attributed to any of the pending partials in the
// sequence terminates. In this case, the state machine transitions to the
// expired state.
func (s *sequenceState) configureFSM() {
	for seqID, expr := range s.seq.Expressions {
		// sequence expression index is the state name
		s.exprs[seqID] = expr.Expr.String()
		// is this the last state?
		if seqID >= len(s.seq.Expressions)-1 {
			s.fsm.
				Configure(seqID).
				Permit(matchTransition, sequenceTerminalState).
				Permit(cancelTransition, sequenceDeadlineState).
				Permit(expireTransition, sequenceExpiredState)
		} else {
			// the previous state can transition to the next one
			// via the match transition, or can either go to the
			// deadline or expired states via cancel and expire
			// transitions respectively
			s.fsm.
				Configure(seqID).
				Permit(matchTransition, seqID+1).
				Permit(cancelTransition, sequenceDeadlineState).
				Permit(expireTransition, sequenceExpiredState)
		}
	}
	// configure reset transitions that are triggered
	// when the final state is reached of when a deadline
	// or sequence expiration happens
	s.fsm.
		Configure(sequenceTerminalState).
		Permit(resetTransition, sequenceInitialState)
	s.fsm.
		Configure(sequenceDeadlineState).
		Permit(resetTransition, sequenceInitialState)
	s.fsm.
		Configure(sequenceExpiredState).
		Permit(resetTransition, sequenceInitialState)
}

func (s *sequenceState) matchTransition(seqID int, e *kevent.Kevent) error {
	s.smu.Lock()
	defer s.smu.Unlock()
	shouldFire := !s.states[seqID]
	if shouldFire {
		return s.fsm.Fire(matchTransition, e)
	}
	return nil
}

func (s *sequenceState) cancelTransition(seqID fsm.State) error {
	return s.fsm.Fire(cancelTransition, seqID)
}

func (s *sequenceState) expireTransition() error {
	return s.fsm.Fire(expireTransition)
}

func (s *sequenceState) isTerminalState() bool {
	isFinal := s.currentState() == sequenceTerminalState
	if isFinal {
		err := s.fsm.Fire(resetTransition)
		if err != nil {
			log.Warnf("unable to transition to initial state: %v", err)
		}
	}
	return isFinal
}

func (s *sequenceState) isInitialState() bool {
	return s.currentState() == s.initialState
}

func (s *sequenceState) currentState() fsm.State {
	return s.fsm.MustState()
}

func (s *sequenceState) expr(state fsm.State) string {
	seqID, ok := state.(int)
	if !ok {
		return ""
	}
	return s.exprs[seqID]
}

// addPartial appends the event that matched the expression at the
// sequence index. If the event arrived out of order, then the isOOO
// parameter is equal to false.
func (s *sequenceState) addPartial(seqID int, e *kevent.Kevent, isOOO bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.partials[seqID]) > maxOutstandingPartials {
		partialBreaches.Add(s.name, 1)
		if !s.isPartialsBreached.Load() {
			log.Warnf("max partials encountered in sequence %s slot [%d]. "+
				"Dropping incoming partial: %s", s.name, seqID, e)
		}
		s.isPartialsBreached.Store(true)
		return
	}
	key := e.PartialKey()
	if key != 0 {
		for _, p := range s.partials[seqID] {
			if key == p.PartialKey() {
				log.Debugf("event %s for tuple %d already in sequence state", e, key)
				return
			}
		}
	}
	if isOOO {
		e.AddMeta(kevent.RuleSequenceOOOKey, true)
	}
	log.Debugf("adding partial to sequence [%s] slot [%d] for expression %q, ooo: %t: %s", s.name, seqID, s.expr(seqID), isOOO, e)
	partialsPerSequence.Add(s.name, 1)
	s.partials[seqID] = append(s.partials[seqID], e)
	sort.Slice(s.partials[seqID], func(n, m int) bool { return s.partials[seqID][n].Timestamp.Before(s.partials[seqID][m].Timestamp) })
}

// gc prunes the sequence partial if it remained
// more time than specified by max span or if max
// span is omitted, the partial is allowed to remain
// in sequence state for four hours.
func (s *sequenceState) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	dur := s.maxSpan
	if dur == 0 {
		dur = maxSequencePartialLifetime
	}
	for idx := range s.exprs {
		for i := len(s.partials[idx]) - 1; i >= 0; i-- {
			if len(s.partials[idx]) > 0 && time.Since(s.partials[idx][i].Timestamp) > dur {
				log.Debugf("garbage collecting partial: [%s] of sequence [%s]", s.partials[idx][i], s.name)
				// remove partial event from the corresponding slot
				s.partials[idx] = append(
					s.partials[idx][:i],
					s.partials[idx][i+1:]...)
				partialsPerSequence.Add(s.name, -1)
			}
		}
	}
}

func (s *sequenceState) clear() {
	s.partials = make(map[int][]*kevent.Kevent)
	s.matches = make(map[int]*kevent.Kevent)
	s.states = make(map[fsm.State]bool)
	s.spanDeadlines = make(map[fsm.State]*time.Timer)
	s.isPartialsBreached.Store(false)
	partialsPerSequence.Delete(s.name)
}

func (s *sequenceState) clearLocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smu.Lock()
	defer s.smu.Unlock()
	s.mmu.Lock()
	defer s.mmu.Unlock()
	s.clear()
}

// next determines whether the next expression in the
// sequence should be evaluated. The expression is evaluated
// if all its upstream sequence expression produced a match and
// the sequence is not stuck in deadline or expired state.
func (s *sequenceState) next(seqID int) bool {
	// always evaluate the first expression in the sequence
	if seqID == 0 {
		return true
	}
	var next bool
	s.smu.RLock()
	defer s.smu.RUnlock()
	for n := 0; n < seqID; n++ {
		next = s.states[n]
		if !next {
			break
		}
	}
	return next && !s.inDeadline.Load() && !s.inExpired.Load()
}

func (s *sequenceState) scheduleMaxSpanDeadline(seqID fsm.State, maxSpan time.Duration) {
	t := time.AfterFunc(maxSpan, func() {
		inState, _ := s.fsm.IsInState(seqID)
		if inState {
			log.Debugf("max span of %v exceded for expression [%s] of sequence [%s]", maxSpan, s.expr(seqID), s.name)
			s.inDeadline.Store(true)
			s.mu.Lock()
			defer s.mu.Unlock()
			s.smu.Lock()
			defer s.smu.Unlock()
			// transitions to deadline state
			err := s.cancelTransition(seqID)
			if err != nil {
				s.inDeadline.Store(false)
				log.Warnf("deadline transition failed: %v", err)
			}
			// transitions from deadline state to initial state
			err = s.fsm.Fire(resetTransition)
			if err != nil {
				log.Warnf("unable to transition to initial state: %v", err)
			}
		}
	})
	s.spanDeadlines[seqID] = t
}

func (s *sequenceState) runSequence(e *kevent.Kevent) bool {
	for i, expr := range s.seq.Expressions {
		// only try to evaluate the expression
		// if upstream expressions have matched
		if !s.next(i) {
			if !s.seq.IsUnordered {
				continue
			}
			// it could be the event arrived out
			// of order because certain provider
			// flushed its buffers first. When this
			// happens the event timestamp serves as
			// a temporal reference.
			// If this sequence expression can evaluate
			// against the current event, mark it as
			// out-of-order and store in partials list
			s.mu.RLock()
			ok := expr.IsEvaluable(e) && s.filter.RunSequence(e, i, s.partials, true)
			s.mu.RUnlock()
			if ok {
				s.addPartial(i, e, true)
			}
			continue
		}

		// prevent running the filter if the expression
		// can't be matched against the current event
		if !expr.IsEvaluable(e) {
			continue
		}

		s.mu.RLock()
		matches := s.filter.RunSequence(e, i, s.partials, false)
		s.mu.RUnlock()

		// append the partial and transition state machine
		if matches {
			s.addPartial(i, e, false)
			err := s.matchTransition(i, e)
			if err != nil {
				matchTransitionErrors.Add(1)
				log.Warnf("match transition failure: %v", err)
			}
			// now try to match all pending out-of-order
			// events from downstream sequence slots if
			// the previous match hasn't reached terminal
			// state
			if s.seq.IsUnordered && s.currentState() != sequenceTerminalState {
				s.mu.RLock()
				for seqID := range s.partials {
					for _, evt := range s.partials[seqID] {
						if !evt.ContainsMeta(kevent.RuleSequenceOOOKey) {
							continue
						}
						matches = s.filter.RunSequence(evt, seqID, s.partials, false)
						// transition the state machine
						if matches {
							err := s.matchTransition(seqID, evt)
							if err != nil {
								matchTransitionErrors.Add(1)
								log.Warnf("out of order match transition failure: %v", err)
							}
							evt.RemoveMeta(kevent.RuleSequenceOOOKey)
						}
					}
				}
				s.mu.RUnlock()
			}
		}

		// if both the terminal state is reached and the partials
		// in the sequence state could be joined by the specified
		// field(s), the rule has matched successfully, and we can
		// collect all events involved in the rule match
		isTerminal := s.isTerminalState()
		if isTerminal {
			setMatch := func(seqID int, e *kevent.Kevent) {
				s.mmu.Lock()
				defer s.mmu.Unlock()
				if s.matches[seqID] == nil {
					s.matches[seqID] = e
				}
			}

			s.mu.RLock()
			for seqID := 0; seqID < len(s.partials); seqID++ {
				for _, outer := range s.partials[seqID] {
					for _, inner := range s.partials[seqID+1] {
						if filter.CompareSeqLink(outer.SequenceLink(), inner.SequenceLink()) {
							setMatch(seqID, outer)
							setMatch(seqID+1, inner)
						}
					}
				}
			}
			s.mu.RUnlock()

			return true
		}
	}
	return false
}

func (s *sequenceState) expire(e *kevent.Kevent) bool {
	if !e.IsTerminateProcess() {
		return false
	}
	canExpire := func(lhs, rhs *kevent.Kevent, isFinalSlot bool) bool {
		// if the TerminateProcess event arrives for the
		// process spawned by CreateProcess, and it pertains
		// to the final sequence slot, it is safe to expire
		// the whole sequence
		if lhs.Type == ktypes.CreateProcess && isFinalSlot {
			p1, _ := lhs.Kparams.GetPid()
			p2, _ := rhs.Kparams.GetPid()
			return p1 == p2
		}
		pid, _ := rhs.Kparams.GetPid()
		return lhs.PID == pid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smu.RLock()
	defer s.smu.RUnlock()

	for idx := range s.exprs {
		for i := len(s.partials[idx]) - 1; i >= 0; i-- {
			if len(s.partials[idx]) > 0 && !canExpire(s.partials[idx][i], e, idx == len(s.exprs)-1) {
				continue
			}
			log.Debugf("removing event originated from %s (%d) "+
				"in partials pertaining to sequence [%s] and slot [%d]",
				e.Kparams.MustGetString(kparams.ProcessName),
				e.Kparams.MustGetPid(),
				s.name,
				idx)
			// remove partial event from the corresponding slot
			s.partials[idx] = append(
				s.partials[idx][:i],
				s.partials[idx][i+1:]...)
			partialsPerSequence.Add(s.name, -1)

			if len(s.partials[idx]) == 0 {
				partialExpirations.Add(s.name, 1)
				log.Debugf("%q sequence expired. All partials retracted", s.name)
				s.inExpired.Store(true)
				err := s.expireTransition()
				if err != nil {
					s.inExpired.Store(false)
					log.Warnf("expire transition failed: %v", err)
				}
				// transitions from expired state to initial state
				err = s.fsm.Fire(resetTransition)
				if err != nil {
					log.Warnf("unable to transition to initial state: %v", err)
				}
				return true
			}
		}
	}

	return false
}
