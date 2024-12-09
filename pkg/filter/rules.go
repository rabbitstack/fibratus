/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package filter

import (
	"context"
	"expvar"
	"fmt"
	fsm "github.com/qmuntal/stateless"
	"github.com/rabbitstack/fibratus/pkg/filter/action"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/atomic"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"sort"
	"sync"
	"time"

	semver "github.com/hashicorp/go-version"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
)

const (
	// maxOutstandingPartials determines the maximum number of partials per sequence index
	maxOutstandingPartials = 1000
)

var (
	filterMatches = expvar.NewMap("filter.matches")
	filtersCount  = expvar.NewInt("filter.filters.count")

	matchTransitionErrors = expvar.NewInt("sequence.match.transition.errors")
	partialsPerSequence   = expvar.NewMap("sequence.partials.count")
	partialExpirations    = expvar.NewMap("sequence.partial.expirations")
	partialBreaches       = expvar.NewMap("sequence.partial.breaches")

	ErrInvalidFilter = func(rule string, err error) error {
		return fmt.Errorf("syntax error in rule %q: \n%v", rule, err)
	}
	ErrRuleAction = func(rule string, err error) error {
		return fmt.Errorf("fail to execute action for %q rule: %v", rule, err)
	}
	ErrIncompatibleFilter = func(rule, v string) error {
		return fmt.Errorf("rule %q needs engine version [%s] but current version is [%s]", rule, v, version.Get())
	}
	ErrMalformedMinEngineVer = func(rule, v string, err error) error {
		return fmt.Errorf("rule %q has a malformed minimum engine version: %s: %v", rule, v, err)
	}

	// sequenceGcInterval determines how often sequence GC kicks in
	sequenceGcInterval = time.Minute
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

	// transitions for match, cancel, reset, and expire triggers
	matchTransition  = fsm.Trigger("match")
	cancelTransition = fsm.Trigger("cancel")
	resetTransition  = fsm.Trigger("reset")
	expireTransition = fsm.Trigger("expire")
)

// Rules stores the compiled filter exprs
// and for each incoming event, it applies
// the corresponding filter to the event.
// If the filter rule has an action, the
// former is executed when the rule fires.
type Rules struct {
	filters map[uint32][]*compiledFilter
	config  *config.Config
	psnap   ps.Snapshotter

	matches   []*ruleMatch
	sequences []*sequenceState

	scavenger *time.Ticker
}

type ruleMatch struct {
	ctx *config.ActionContext
}

type compiledFilter struct {
	filter Filter
	ss     *sequenceState
	config *config.FilterConfig
}

// sequenceState represents the state of the
// ordered sequence of multiple events that
// may have time-frame constraints. A deterministic
// finite state machine tracks the matching status of
// each rule (state) in the machine.
type sequenceState struct {
	name    string
	maxSpan time.Duration

	// partials keeps the state of all matched events per expression
	partials map[uint16][]*kevent.Kevent
	// mu guards the partials map
	mu sync.RWMutex

	// matches stores only the event that matched
	// the upstream partials. These events will be propagated
	// in the rule action context
	matches map[uint16]*kevent.Kevent
	// mmu guards the matches map
	mmu sync.RWMutex

	fsm *fsm.StateMachine

	// rule to rule index mapping. Indices start at 1
	idxs          map[fsm.State]uint16
	spanDeadlines map[fsm.State]*time.Timer
	inDeadline    atomic.Bool
	inExpired     atomic.Bool
	initialState  fsm.State

	// matchedRules keeps the mapping between rule indexes and
	// their matches. Indices start at 1
	matchedRules map[uint16]bool
	// mrm guards the matchedRules map
	mrm sync.RWMutex
}

func newSequenceState(name, initialState string, maxSpan time.Duration) *sequenceState {
	ss := &sequenceState{
		name:          name,
		maxSpan:       maxSpan,
		partials:      make(map[uint16][]*kevent.Kevent),
		matchedRules:  make(map[uint16]bool),
		matches:       make(map[uint16]*kevent.Kevent),
		idxs:          make(map[fsm.State]uint16),
		spanDeadlines: make(map[fsm.State]*time.Timer),
		initialState:  fsm.State(initialState),
		inDeadline:    atomic.MakeBool(false),
	}

	ss.initFSM(initialState)

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

func (s *sequenceState) initFSM(initialState string) {
	s.fsm = fsm.NewStateMachine(initialState)
	s.fsm.OnTransitioned(func(ctx context.Context, transition fsm.Transition) {
		// schedule span deadline for the current state unless initial/meta states
		if s.maxSpan != 0 && s.isStateSchedulable(s.currentState()) {
			log.Debugf("scheduling max span deadline of %v for rule %s", s.maxSpan, s.currentState())
			s.scheduleMaxSpanDeadline(s.currentState(), s.maxSpan)
		}
		// if the sequence was deadlined/expired, we can disable the deadline
		// status when the first rule in the sequence is reevaluated
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
			log.Debugf("state trigger from rule [%s]", transition.Source)
			// a match occurred from current to next state.
			// Stop deadline execution for the old current state
			if span, ok := s.spanDeadlines[transition.Source]; ok {
				log.Debugf("stopped max span deadline for rule %s", transition.Source)
				span.Stop()
				delete(s.spanDeadlines, transition.Source)
			}
			// save rule matches
			s.matchedRules[s.idxs[transition.Source]] = true
		}
	})
}

func (s *sequenceState) matchTransition(rule string, kevt *kevent.Kevent) error {
	s.mrm.Lock()
	defer s.mrm.Unlock()
	shouldFire := !s.matchedRules[s.idxs[rule]]
	if shouldFire {
		return s.fsm.Fire(matchTransition, kevt)
	}
	return nil
}

func (s *sequenceState) cancelTransition(rule fsm.State) error {
	return s.fsm.Fire(cancelTransition, rule)
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

func (s *sequenceState) addPartial(rule string, kevt *kevent.Kevent, outOfOrder bool) {
	i := s.idxs[rule]
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.partials[i]) > maxOutstandingPartials {
		partialBreaches.Add(s.name, 1)
		log.Warnf("max partials encountered in sequence %s slot [%d]. "+
			"Dropping incoming partial", s.name, s.idxs[rule])
		return
	}
	key := kevt.PartialKey()
	if key != 0 {
		for _, p := range s.partials[i] {
			if key == p.PartialKey() {
				log.Debugf("%s event tuple already in sequence state", kevt.Name)
				return
			}
		}
	}
	if outOfOrder {
		kevt.AddMeta(kevent.RuleExpressionKey, rule)
		kevt.AddMeta(kevent.RuleSequenceOutOfOrderKey, true)
	}
	log.Debugf("adding partial to slot [%d] for rule %q: %s", i, rule, kevt)
	partialsPerSequence.Add(s.name, 1)
	s.partials[i] = append(s.partials[i], kevt)
	sort.Slice(s.partials[i], func(n, m int) bool { return s.partials[i][n].Timestamp.Before(s.partials[i][m].Timestamp) })
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
	for _, idx := range s.idxs {
		for i := len(s.partials[idx]) - 1; i >= 0; i-- {
			if len(s.partials[idx]) > 0 && time.Since(s.partials[idx][i].Timestamp) > dur {
				log.Debugf("garbage collecting partial: [%s]", s.partials[idx][i])
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
	s.partials = make(map[uint16][]*kevent.Kevent)
	s.matches = make(map[uint16]*kevent.Kevent)
	s.matchedRules = make(map[uint16]bool)
	s.spanDeadlines = make(map[fsm.State]*time.Timer)
	partialsPerSequence.Delete(s.name)
}

func (s *sequenceState) clearLocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mrm.Lock()
	defer s.mrm.Unlock()
	s.mmu.Lock()
	defer s.mmu.Unlock()
	s.clear()
}

// next determines whether the next rule in the
// sequence should be evaluated. The rule is evaluated
// if all its upstream sequence rules produced a match and
// the sequence is not stuck in deadline or expired state.
func (s *sequenceState) next(i int) bool {
	// always evaluate the first rule in the sequence
	if i == 0 {
		return true
	}
	var next bool
	s.mrm.RLock()
	defer s.mrm.RUnlock()
	for n := 0; n < i; n++ {
		next = s.matchedRules[uint16(n+1)]
		if !next {
			break
		}
	}
	return next && !s.inDeadline.Load() && !s.inExpired.Load()
}

func (s *sequenceState) scheduleMaxSpanDeadline(rule fsm.State, maxSpan time.Duration) {
	t := time.AfterFunc(maxSpan, func() {
		inState, _ := s.fsm.IsInState(rule)
		if inState {
			log.Infof("max span of %v exceded for rule %s", maxSpan, rule)
			s.inDeadline.Store(true)
			s.mu.Lock()
			defer s.mu.Unlock()
			s.mrm.Lock()
			defer s.mrm.Unlock()
			// transitions to deadline state
			err := s.cancelTransition(rule)
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
	s.spanDeadlines[rule] = t
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
	s.mrm.RLock()
	defer s.mrm.RUnlock()
	for _, idx := range s.idxs {
		for i := len(s.partials[idx]) - 1; i >= 0; i-- {
			if len(s.partials[idx]) > 0 && !canExpire(s.partials[idx][i], e, idx == uint16(len(s.idxs))) {
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

func newCompiledFilter(f Filter, filterConfig *config.FilterConfig, ss *sequenceState) *compiledFilter {
	return &compiledFilter{config: filterConfig, filter: f, ss: ss}
}

// isScoped determines if this filter is scoped, i.e. it has the event name or category
// conditions.
func (f compiledFilter) isScoped() bool {
	for name := range f.filter.GetStringFields() {
		if name == fields.KevtName || name == fields.KevtCategory {
			return true
		}
	}
	return false
}

// run execute the filter with either simple or sequence expressions.
func (f compiledFilter) run(kevt *kevent.Kevent, i int, rawMatch, lock bool) bool {
	if f.ss != nil {
		if lock {
			f.ss.mu.RLock()
			defer f.ss.mu.RUnlock()
		}
		return f.filter.RunSequence(kevt, uint16(i), f.ss.partials, rawMatch)
	}
	return f.filter.Run(kevt)
}

// NewRules produces a fresh rules engine instance.
func NewRules(psnap ps.Snapshotter, config *config.Config) *Rules {
	rules := &Rules{
		filters:   make(map[uint32][]*compiledFilter),
		matches:   make([]*ruleMatch, 0),
		sequences: make([]*sequenceState, 0),
		psnap:     psnap,
		config:    config,
		scavenger: time.NewTicker(sequenceGcInterval),
	}

	go rules.gcSequences()

	return rules
}

// Compile loads macros and rules from all
// indicated resources and compiles the filters.
// It also sets up the state machine transitions
// for sequence rules.
func (r *Rules) Compile() (*config.RulesCompileResult, error) {
	if err := r.config.Filters.LoadMacros(); err != nil {
		return nil, err
	}
	if err := r.config.Filters.LoadFilters(); err != nil {
		return nil, err
	}

	for _, f := range r.config.GetFilters() {
		if f.IsDisabled() {
			log.Warnf("[%s] rule is disabled", f.Name)
			continue
		}

		filtersCount.Add(1)

		// compile filter and for sequence rules
		// configure the FSM states and transitions
		fltr := New(f.Condition, r.config, WithPSnapshotter(r.psnap))
		err := fltr.Compile()
		if err != nil {
			return nil, ErrInvalidFilter(f.Name, err)
		}
		// check version requirements
		if !version.IsDev() {
			minEngineVer, err := semver.NewSemver(f.MinEngineVersion)
			if err != nil {
				return nil, ErrMalformedMinEngineVer(f.Name, f.MinEngineVersion, err)
			}
			if minEngineVer.GreaterThan(version.Sem()) {
				return nil, ErrIncompatibleFilter(f.Name, f.MinEngineVersion)
			}
		}
		for _, field := range fltr.GetFields() {
			deprecated, d := fields.IsDeprecated(field)
			if deprecated {
				log.Warnf("%s rule uses the [%s] field which "+
					"was deprecated starting from version %s. "+
					"Please consider migrating to %s field(s) "+
					"because [%s] will be removed in future versions.",
					f.Name, field, d.Since, d.Fields, field)
			}
		}
		cf := newCompiledFilter(fltr, f, configureFSM(f, fltr))
		if fltr.IsSequence() && cf.ss != nil {
			// store the sequences in rules
			// for more convenient tracking
			r.sequences = append(r.sequences, cf.ss)
		}

		// traverse all event name or category fields and determine
		// the event type from the filter field name expression.
		// We end up with a map of rules indexed by event name
		// or event category hash
		if !cf.isScoped() {
			log.Warnf("%q rule doesn't have "+
				"event type or event category condition! "+
				"This rule is being discarded by "+
				"the engine. Please consider narrowing the "+
				"scope of this rule by including the `kevt.name` "+
				"or `kevt.category` condition",
				f.Name)
			continue
		}
		for name, values := range fltr.GetStringFields() {
			for _, v := range values {
				if name == fields.KevtName || name == fields.KevtCategory {
					hash := hashers.FnvUint32([]byte(v))
					r.filters[hash] = append(r.filters[hash], cf)
				}
			}
		}
	}

	if len(r.filters) == 0 {
		return nil, nil
	}

	return r.buildCompileResult(), nil
}

func configureFSM(filter *config.FilterConfig, f Filter) *sequenceState {
	if !f.IsSequence() {
		return nil
	}
	seq := f.GetSequence()
	expressions := seq.Expressions
	if len(expressions) == 0 {
		return nil
	}
	initialState := expressions[0].Expr.String()
	seqState := newSequenceState(filter.Name, initialState, seq.MaxSpan)
	// setup finite state machine states. The last rule
	// in the sequence transitions to the terminal state
	// if all rules match
	for i, expr := range expressions {
		n := expr.Expr.String()
		seqState.idxs[n] = uint16(i + 1)
		if i >= len(expressions)-1 {
			seqState.fsm.
				Configure(n).
				Permit(matchTransition, sequenceTerminalState).
				Permit(cancelTransition, sequenceDeadlineState).
				Permit(expireTransition, sequenceExpiredState)
		} else {
			seqState.fsm.
				Configure(n).
				Permit(matchTransition, expressions[i+1].Expr.String()).
				Permit(cancelTransition, sequenceDeadlineState).
				Permit(expireTransition, sequenceExpiredState)
		}
	}
	// configure reset transitions that are triggered
	// when the final state is reached of when a deadline
	// or sequence expiration happens
	seqState.fsm.
		Configure(sequenceTerminalState).
		Permit(resetTransition, initialState)
	seqState.fsm.
		Configure(sequenceDeadlineState).
		Permit(resetTransition, initialState)
	seqState.fsm.
		Configure(sequenceExpiredState).
		Permit(resetTransition, initialState)
	return seqState
}

func (r *Rules) buildCompileResult() *config.RulesCompileResult {
	rs := &config.RulesCompileResult{}

	m := make(map[ktypes.Ktype]bool)
	events := make([]ktypes.Ktype, 0)

	for _, fltrs := range r.filters {
		for _, cf := range fltrs {
			rs.NumberRules++
			for name, values := range cf.filter.GetStringFields() {
				for _, v := range values {
					if name == fields.KevtName || name == fields.KevtCategory {
						types := ktypes.KeventNameToKtypes(v)
						for _, typ := range types {
							switch typ.Category() {
							case ktypes.Process:
								rs.HasProcEvents = true
							case ktypes.Thread:
								rs.HasThreadEvents = true
							case ktypes.Image:
								rs.HasImageEvents = true
							case ktypes.File:
								rs.HasFileEvents = true
							case ktypes.Net:
								rs.HasNetworkEvents = true
							case ktypes.Registry:
								rs.HasRegistryEvents = true
							case ktypes.Mem:
								rs.HasMemEvents = true
							case ktypes.Handle:
								rs.HasHandleEvents = true
							}
							if typ == ktypes.MapViewFile || typ == ktypes.UnmapViewFile {
								rs.HasVAMapEvents = true
							}
							if typ == ktypes.OpenProcess || typ == ktypes.OpenThread || typ == ktypes.SetThreadContext ||
								typ == ktypes.CreateSymbolicLinkObject {
								rs.HasAuditAPIEvents = true
							}
							if typ.Subcategory() == ktypes.DNS {
								rs.HasDNSEvents = true
							}
							if m[typ] {
								continue
							}
							events = append(events, typ)
							m[typ] = true
						}
					}
				}
			}
		}
	}

	rs.UsedEvents = events
	return rs
}

// hasRules checks if rules were loaded into
// the engine. If there are no rules the event is
// forwarded to the aggregator.
func (r *Rules) hasRules() bool { return len(r.filters) > 0 }

// findFilters collects all compiled filters for a
// particular event type or category. If no filters
// are found the event is rejected from the aggregator
// batch.
func (r *Rules) findFilters(evt *kevent.Kevent) []*compiledFilter {
	filters1 := r.filters[evt.Type.Hash()]
	filters2 := r.filters[evt.Category.Hash()]
	if filters1 == nil && filters2 == nil {
		return nil
	}
	return append(filters1, filters2...)
}

func (*Rules) CanEnqueue() bool { return true }

func (r *Rules) ProcessEvent(evt *kevent.Kevent) (bool, error) {
	if !r.hasRules() {
		return true, nil
	}
	if evt.IsTerminateProcess() {
		// expire all sequences if the
		// process referenced in any
		// partials has terminated
		for _, seq := range r.sequences {
			seq.expire(evt)
		}
	}
	return r.runRules(r.findFilters(evt), evt), nil
}

func (r *Rules) gcSequences() {
	for {
		<-r.scavenger.C
		for _, seq := range r.sequences {
			seq.gc()
		}
	}
}

func (r *Rules) runSequence(kevt *kevent.Kevent, f *compiledFilter) bool {
	seq := f.filter.GetSequence()
	if seq == nil {
		return false
	}
	for i, expr := range seq.Expressions {
		// only try to evaluate the expression
		// if upstream expressions have matched
		if !f.ss.next(i) {
			if !seq.IsUnordered {
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
			if expr.IsEvaluable(kevt) && f.run(kevt, i, true, true) {
				f.ss.addPartial(expr.Expr.String(), kevt, true)
			}
			continue
		}
		// prevent running the filter if the expression
		// can't be matched against the current event
		if !expr.IsEvaluable(kevt) {
			continue
		}
		rule := expr.Expr.String()
		matches := f.run(kevt, i, false, true)
		// append the partial and transition state machine
		if matches {
			f.ss.addPartial(rule, kevt, false)
			err := f.ss.matchTransition(rule, kevt)
			if err != nil {
				matchTransitionErrors.Add(1)
				log.Warnf("match transition failure: %v", err)
			}
			// now try to match all pending out-of-order
			// events from downstream sequence slots if
			// the previous match hasn't reached terminal
			// state
			if seq.IsUnordered && f.ss.currentState() != sequenceTerminalState {
				r.matchUnorderedPartials(f)
			}
		}
	}
	// if both the terminal state is reached and the partials
	// in the sequence state could be joined by the specified
	// field(s), the rule has matched successfully, and we can
	// collect all events involved in the rule match
	isTerminal := f.ss.isTerminalState()
	if isTerminal {
		f.ss.mu.RLock()
		defer f.ss.mu.RUnlock()
		nseqs := uint16(len(f.ss.partials))

		setMatch := func(idx uint16, e *kevent.Kevent) {
			f.ss.mmu.Lock()
			defer f.ss.mmu.Unlock()
			if f.ss.matches[idx] == nil {
				f.ss.matches[idx] = e
			}
		}

		for i := uint16(1); i < nseqs+1; i++ {
			for _, outer := range f.ss.partials[i] {
				for _, inner := range f.ss.partials[i+1] {
					if compareSeqJoin(outer.SequenceBy(), inner.SequenceBy()) {
						setMatch(i, outer)
						setMatch(i+1, inner)
					}
				}
			}
		}
	}
	return isTerminal
}

func (r *Rules) matchUnorderedPartials(f *compiledFilter) {
	f.ss.mu.Lock()
	defer f.ss.mu.Unlock()
	for n, partials := range f.ss.partials {
		for _, partial := range partials {
			if !partial.ContainsMeta(kevent.RuleSequenceOutOfOrderKey) {
				continue
			}
			matches := f.run(partial, int(n)-1, false, false)
			rule := partial.GetMetaAsString(kevent.RuleExpressionKey)
			// transition the state machine
			if matches {
				err := f.ss.matchTransition(rule, partial)
				if err != nil {
					matchTransitionErrors.Add(1)
					log.Warnf("out of order match transition failure: %v", err)
				}
				partial.RemoveMeta(kevent.RuleSequenceOutOfOrderKey)
			}
		}
	}
}

func (r *Rules) triggerSequencesInFilters(e *kevent.Kevent, filters []*compiledFilter) {
	for _, f := range filters {
		if !f.filter.IsSequence() || f.ss == nil {
			continue
		}
		if r.runSequence(e, f) {
			r.appendMatch(f.config, f.ss.events()...)
			f.ss.clearLocked()
		}
	}
}

func (r *Rules) runRules(filters []*compiledFilter, kevt *kevent.Kevent) bool {
	for i, f := range filters {
		var match bool
		if f.ss != nil {
			match = r.runSequence(kevt, f)
		} else {
			match = f.run(kevt, i, false, false)
			if match {
				// transition sequence states since a match
				// in a simple rule could trigger multiple
				// matches in sequence rules
				r.triggerSequencesInFilters(kevt, filters)
			}
		}
		if match {
			if f.ss != nil {
				r.appendMatch(f.config, f.ss.events()...)
				f.ss.clearLocked()
			} else {
				r.appendMatch(f.config, kevt)
			}
			err := r.processActions()
			if err != nil {
				log.Errorf("unable to execute rule action: %v", err)
			}
			return true
		}
	}
	return false
}

// processActions executes rule actions
// on behalf of rule matches. Actions are
// categorized into implicit and explicit
// actions.
// Sending an alert is an implicit action
// carried out each time there is a rule
// match. Other actions are executed if
// defined in the rule definition.
func (r *Rules) processActions() error {
	defer r.clearMatches()
	for _, m := range r.matches {
		f, evts := m.ctx.Filter, m.ctx.Events
		filterMatches.Add(f.Name, 1)
		log.Debugf("[%s] rule matched", f.Name)
		err := action.Emit(m.ctx, f.Name, InterpolateFields(f.Output, evts), f.Severity, f.Tags)
		if err != nil {
			return ErrRuleAction(f.Name, err)
		}

		actions, err := f.DecodeActions()
		if err != nil {
			return err
		}
		for _, act := range actions {
			switch act.(type) {
			case config.KillAction:
				log.Infof("executing kill action: pids=%v rule=%s", m.ctx.UniquePids(), f.Name)
				if err := action.Kill(m.ctx.UniquePids()); err != nil {
					return ErrRuleAction(f.Name, err)
				}
			}
		}
	}
	return nil
}

func (r *Rules) appendMatch(f *config.FilterConfig, evts ...*kevent.Kevent) {
	for _, evt := range evts {
		evt.AddMeta(kevent.RuleNameKey, f.Name)
		for k, v := range f.Labels {
			evt.AddMeta(kevent.MetadataKey(k), v)
		}
	}
	ctx := &config.ActionContext{
		Events: evts,
		Filter: f,
	}
	r.matches = append(r.matches, &ruleMatch{ctx: ctx})
}

func (r *Rules) clearMatches() {
	r.matches = make([]*ruleMatch, 0)
}
