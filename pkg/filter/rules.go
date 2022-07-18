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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"expvar"
	"fmt"
	fsm "github.com/qmuntal/stateless"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/funcmap"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
)

var (
	excludeOrFilterMatches    = expvar.NewMap("filter.exclude.or.matches")
	excludeAndFilterMatches   = expvar.NewMap("filter.exclude.and.matches")
	includeOrFilterMatches    = expvar.NewMap("filter.include.or.matches")
	includeAndFilterMatches   = expvar.NewMap("filter.include.and.matches")
	filterGroupsCount         = expvar.NewInt("filter.groups.count")
	filterGroupsCountByPolicy = expvar.NewMap("filter.groups.count.policy")
	filtersCount              = expvar.NewInt("filter.filters.count")

	ErrInvalidFilter = func(rule, group string, err error) error {
		return fmt.Errorf("invalid filter %q in %q group: %v", rule, group, err)
	}
)

var (
	// sequenceTerminalState represents the final state in the FSM.
	// This state is transitioned when the last rule in the group
	// produces a match
	sequenceTerminalState = fsm.State("terminal")
	// sequenceDeadlineState represents the state to which other
	// states transition if the rule's max span is reached
	sequenceDeadlineState = fsm.State("deadline")

	// transitions for match, deadline and reset triggers
	matchTransition    = fsm.Trigger("match")
	deadlineTransition = fsm.Trigger("deadline")
	resetTransition    = fsm.Trigger("reset")
)

// Rules stores the compiled filter groups
// and for each incoming event, it applies
// the corresponding filtering policies to
// the event, dropping the event or passing
// it accordingly. If the filter rule has
// an action, the former is executed when the
// rule fires.
type Rules struct {
	filterGroups   map[uint32]filterGroups
	sequences      map[string]*sequenceState
	sequenceGroups []*filterGroup
	config         *config.Config
}

type filterGroup struct {
	group   config.FilterGroup
	filters []compiledFilter
}

type compiledFilter struct {
	filter Filter
	config *config.FilterConfig
}

// sequenceState represents the state of the
// ordered sequence of multiple events that
// may have time-frame constraints. A deterministic
// finite state machine tracks the matching status of
// each rule (state) in the machine.
type sequenceState struct {
	// keeps the state of matched events per rule index
	matchedEvents map[uint16][]*kevent.Kevent
	// reducedMatches stores only the event that matched
	// the upstream partials. These events will be propagated
	// in the rule action context
	reducedMatches map[uint16]*kevent.Kevent
	fsm            *fsm.StateMachine
	idxs           map[string]uint16
	maxSpans       map[fsm.State]time.Duration
	spanDeadlines  map[fsm.State]*time.Timer
	inDeadline     uint64
	initialState   fsm.State
	// matchedRules keeps the mapping between rule indexes and
	// their matches.
	matchedRules   map[uint16]bool
}

func newSequenceState(initialState string) *sequenceState {
	ss := &sequenceState{
		matchedEvents:  make(map[uint16][]*kevent.Kevent),
		matchedRules:   make(map[uint16]bool),
		reducedMatches: make(map[uint16]*kevent.Kevent),
		idxs:           make(map[string]uint16),
		maxSpans:       make(map[fsm.State]time.Duration),
		spanDeadlines:  make(map[fsm.State]*time.Timer),
		initialState:   fsm.State(initialState),
	}

	ss.initFSM(initialState)

	return ss
}

func (s *sequenceState) initFSM(initialState string) {
	s.fsm = fsm.NewStateMachine(initialState)
	s.fsm.OnTransitioned(func(ctx context.Context, transition fsm.Transition) {
		if dur, ok := s.maxSpans[transition.Destination]; ok {
			s.scheduleMaxSpanDeadline(transition.Destination, dur)
		}
		if span, ok := s.spanDeadlines[transition.Source]; ok {
			span.Stop()
			delete(s.spanDeadlines, transition.Source)
		}
		// the sequence is stuck in deadline until the reset transitions
		// to initial state and initial state transitions to the next one
		if transition.Trigger == resetTransition && transition.Destination == s.initialState {
			atomic.StoreUint64(&s.inDeadline, 0)
			s.clearMatched()
		}
		if transition.Trigger == matchTransition {
			s.matchedRules[s.idxs[transition.Source.(string)]] = true
		}
	})
}

func (s *sequenceState) matchTransition(kevt *kevent.Kevent) error {
	return s.fsm.Fire(matchTransition, kevt)
}

func (s *sequenceState) deadlineTransition(rule fsm.State) error {
	return s.fsm.Fire(deadlineTransition, rule)
}

func (s *sequenceState) isTerminalState() bool {
	isFinal := s.fsm.MustState() == sequenceTerminalState
	if isFinal {
		err := s.fsm.Fire(resetTransition)
		if err != nil {
			log.Warnf("unable to transition to initial state: %v", err)
		}
	}
	return isFinal
}

func (s *sequenceState) isInitialState() bool {
	return s.fsm.MustState() == s.initialState
}

func (s *sequenceState) addMatched(rule string, kevt *kevent.Kevent) {
	s.matchedEvents[s.idxs[rule]] = append(s.matchedEvents[s.idxs[rule]], kevt)
}

func (s *sequenceState) getMatched(rule string) map[uint16][]*kevent.Kevent {
	i := s.idxs[rule]
	// if this is the first rule in the sequence we don't
	// feed back it with partial matches. Propagation is
	// only required for downstream filters
	if i == 1 {
		return nil
	}
	n := i - 1
	partials := make(map[uint16][]*kevent.Kevent)
	for n > 0 {
		partials[n] = s.matchedEvents[n]
		n--
	}
	return partials
}

func (s *sequenceState) clearMatched() {
	s.matchedEvents = make(map[uint16][]*kevent.Kevent)
	s.reducedMatches = make(map[uint16]*kevent.Kevent)
	s.matchedRules = make(map[uint16]bool)
}

// shouldRun determines whether the next rule in the
// sequence should be evaluated.
func (s *sequenceState) shouldRun(i int) bool {
	// always evaluate the first rule in the sequence
	if i == 0 {
		return true
	}
	return s.matchedRules[uint16(i)]
}

func (s *sequenceState) scheduleMaxSpanDeadline(rule fsm.State, maxSpan time.Duration) {
	t := time.AfterFunc(maxSpan, func() {
		inState, _ := s.fsm.IsInState(rule)
		if inState {
			log.Infof("max span of %v exceded for rule %s", maxSpan, rule)
			atomic.StoreUint64(&s.inDeadline, 1)
			// transitions to deadline state
			err := s.deadlineTransition(rule)
			if err != nil {
				atomic.StoreUint64(&s.inDeadline, 0)
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

func (s *sequenceState) deadlined() bool { return atomic.LoadUint64(&s.inDeadline) > 0 }

func newFilterGroup(g config.FilterGroup, filters []compiledFilter) *filterGroup {
	return &filterGroup{group: g, filters: filters}
}

func newCompiledFilter(f Filter, filterConfig *config.FilterConfig) compiledFilter {
	return compiledFilter{config: filterConfig, filter: f}
}

// run execute the filter and returns the matching partial index along with
// the partial event that produced a match.
//
// Example assumes the following partials:
//
// partials[1] = {e1, e2, e3, e4}
//
// If the second filter in the sequence matches on the event e3 in the partials
// index 1, then this method would return the (true, 1, e3) tuple.
func (f compiledFilter) run(kevt *kevent.Kevent, partials map[uint16][]*kevent.Kevent) (bool, uint16, *kevent.Kevent) {
	if len(partials) > 0 {
		return f.filter.RunPartials(kevt, partials)
	}
	return f.filter.Run(kevt), 0, kevt
}

type filterGroups []*filterGroup

func (groups filterGroups) hasIncludePolicy(kevt *kevent.Kevent) bool {
	for _, g := range groups {
		if g.group.Selector.Type == kevt.Type ||
			g.group.Selector.Category == kevt.Category {
			if g.group.Policy == config.IncludePolicy {
				return true
			}
		}
	}
	return false
}

func (groups filterGroups) hasSequencePolicy() bool {
	for _, g := range groups {
		if g.group.Policy == config.SequencePolicy {
			return true
		}
	}
	return false
}

// NewRules produces a fresh rules instance.
func NewRules(c *config.Config) Rules {
	rules := Rules{
		filterGroups:   make(map[uint32]filterGroups),
		sequences:      make(map[string]*sequenceState),
		sequenceGroups: make([]*filterGroup, 0),
		config:         c,
	}
	return rules
}

func expr(c *config.FilterConfig) string {
	if c.Condition != "" {
		return c.Condition
	}
	return c.Def
}

// Compile loads the filter groups from all files
// and creates the filters for each filter group.
func (r *Rules) Compile() error {
	groups, err := r.config.Filters.LoadGroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if !group.Enabled {
			continue
		}
		filterGroupsCount.Add(1)
		filterGroupsCountByPolicy.Add(group.Policy.String(), 1)
		// compute the hash depending on whether the type or category
		// is given in the group selector. For sequence group policies
		// we don't really care about the selector because these groups
		// must attract all event types. In this case the hash is the
		// filter group hash.
		var hash uint32
		if group.Policy == config.SequencePolicy {
			hash = group.Hash()
		} else {
			hash = group.Selector.Hash()
		}
		// compile filters and populate the groups. Additionally, for
		// sequence policies we have to configure the FSM states and
		// transitions.
		initialState := group.FromStrings[0].Name
		seqState := newSequenceState(initialState)
		filters := make([]compiledFilter, 0, len(group.FromStrings))
		for i, filterConfig := range group.FromStrings {
			rule := filterConfig.Name
			f := New(expr(filterConfig), r.config)
			if err := f.Compile(); err != nil {
				return ErrInvalidFilter(rule, group.Name, err)
			}
			// setup finite state machine states. The last rule
			// in the sequence transitions to the terminal state
			// if all rules match
			if group.Policy == config.SequencePolicy {
				seqState.idxs[rule] = uint16(i + 1)
				// schedule maximum span deadline
				if filterConfig.MaxSpan != 0 {
					seqState.maxSpans[rule] = filterConfig.MaxSpan
				}
				if i >= len(group.FromStrings)-1 {
					seqState.fsm.Configure(rule).
						Permit(matchTransition, sequenceTerminalState).
						Permit(deadlineTransition, sequenceDeadlineState)
				} else {
					seqState.fsm.Configure(rule).
						Permit(matchTransition, group.FromStrings[i+1].Name).
						Permit(deadlineTransition, sequenceDeadlineState)
				}
			}
			filters = append(filters, newCompiledFilter(f, filterConfig))
			filtersCount.Add(1)
		}
		// initialize filter groups
		fg := newFilterGroup(group, filters)
		r.filterGroups[hash] = append(r.filterGroups[hash], fg)
		if group.Policy == config.SequencePolicy {
			// configure reset transitions that are triggered
			// when the final state is reached of when a deadline happens
			seqState.fsm.Configure(sequenceTerminalState).Permit(resetTransition, initialState)
			seqState.fsm.Configure(sequenceDeadlineState).Permit(resetTransition, initialState)
			r.sequences[group.Name] = seqState
			r.sequenceGroups = append(r.sequenceGroups, fg)
		}
	}
	return nil
}

func (r *Rules) findFilterGroups(kevt *kevent.Kevent) filterGroups {
	groups1 := r.filterGroups[kevt.Type.Hash()]
	groups2 := r.filterGroups[kevt.Category.Hash()]
	if groups1 == nil && groups2 == nil {
		return r.sequenceGroups
	}
	if len(r.sequenceGroups) > 0 {
		return append(groups1, append(groups2, r.sequenceGroups...)...)
	}
	return append(groups1, groups2...)
}

func (r *Rules) Fire(kevt *kevent.Kevent) bool {
	// if there are no filter groups we assume no group files were
	// defined or specified in the config, so, the default behaviour
	// in such cases is to pass the event and hand over it to the CLI
	// filter
	if len(r.filterGroups) == 0 {
		return true
	}
	// find filter groups for a particular event type, category or
	// sequence groups. Events are dropped by default if no groups
	// are found
	groups := r.findFilterGroups(kevt)
	if len(groups) == 0 {
		return false
	}
	// exclude policies take precedence over
	// groups with include policies, so we first
	// evaluate those. If no filter matches occur,
	// we let pass the event but only if there are
	// no groups with include/sequence policies
	ok := r.runRules(groups, config.ExcludePolicy, kevt)
	if ok {
		return false
	}

	if !groups.hasIncludePolicy(kevt) && !groups.hasSequencePolicy() {
		return true
	}

	// apply include policies. At this point none of
	// the groups with exclude policies got matched
	ok = r.runRules(groups, config.IncludePolicy, kevt)
	if ok {
		return true
	}

	// finally, evaluate sequence policies
	return r.runRules(groups, config.SequencePolicy, kevt)
}

func (r *Rules) runRules(groups filterGroups, policy config.FilterGroupPolicy, kevt *kevent.Kevent) bool {
nextGroup:
	for _, g := range groups {
		if g.group.Policy != policy {
			continue
		}
		// sequence policies leverage stateful event tracking.
		// All rules in the sequence have to match in order to
		// promote the group.
		if g.group.Policy == config.SequencePolicy {
			seqState := r.sequences[g.group.Name]
			if seqState == nil {
				continue
			}
			// if the sequence transitioned through deadline state
			// we can reject any further rule evaluations and clear
			// all matched event tuples
			if seqState.deadlined() {
				seqState.clearMatched()
				return false
			}
			for i, f := range g.filters {
				// run the filter only if the previous rule matched
				if !seqState.shouldRun(i) {
					return false
				}
				rule := f.config.Name
				ok, idx, e := f.run(kevt, seqState.getMatched(rule))
				if ok {
					seqState.addMatched(rule, kevt)
					seqState.reducedMatches[idx] = e
					err := seqState.matchTransition(kevt)
					if err != nil {
						log.Warnf("match transition: %v", err)
					}
				}
			}
			done := seqState.isTerminalState()
			if done {
				seqState.clearMatched()
			}
			return done
		}
		var andMatched bool
		// process include/exclude filter groups. Each of them
		// may have `or` or `and` relation types to promote the
		// group upon first match or either all rules in the group
		// need to match
		for _, f := range g.filters {
			ok, _, _ := f.run(kevt, nil)

			switch g.group.Policy {
			case config.ExcludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if ok {
						excludeOrFilterMatches.Add(f.config.Name, 1)
						return true
					}
				case config.AndRelation:
					if !ok {
						// jump to the next exclude group
						continue nextGroup
					}
					andMatched = true
				}
			case config.IncludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if ok {
						includeOrFilterMatches.Add(f.config.Name, 1)
						err := runFilterAction(kevt, g.group, f.config)
						if err != nil {
							log.Warnf("unable to execute %q rule action: %v", f.config.Name, err)
						}
						// attach rule and group meta
						kevt.AddMeta(kevent.RuleNameKey, f.config.Name)
						kevt.AddMeta(kevent.RuleGroupKey, g.group.Name)
						return true
					}
				case config.AndRelation:
					if !ok {
						// jump to the next include group
						continue nextGroup
					}
					andMatched = true
				}
			}
		}
		// got a match on the `and` relation group
		if andMatched {
			switch g.group.Policy {
			case config.ExcludePolicy:
				for _, f := range g.filters {
					excludeAndFilterMatches.Add(f.config.Name, 1)
				}
			case config.IncludePolicy:
				for _, f := range g.filters {
					includeAndFilterMatches.Add(f.config.Name, 1)
					err := runFilterAction(kevt, g.group, f.config)
					if err != nil {
						log.Warnf("unable to execute %q rule action: %v", f.config.Name, err)
					}
				}
			}
			return true
		}
	}

	return false
}

// ActionContext is the convenient structure
// for grouping the event that resulted in
// matched filter along with filter group
// information.
type ActionContext struct {
	Kevt   *kevent.Kevent
	Filter *config.FilterConfig
	Group  config.FilterGroup
}

// runFilterAction executes the template associated with the filter
// that has produced a match in one of the include groups.
func runFilterAction(kevt *kevent.Kevent, group config.FilterGroup, filter *config.FilterConfig) error {
	if filter.Action == "" {
		return nil
	}
	action, err := base64.StdEncoding.DecodeString(filter.Action)
	if err != nil {
		return fmt.Errorf("corrupted filter action: %v", err)
	}

	fmap := funcmap.New()
	funcmap.InitFuncs(fmap)
	tmpl, err := template.New(filter.Name).Funcs(fmap).Parse(string(action))
	if err != nil {
		return err
	}
	ctx := &ActionContext{
		Kevt:   kevt,
		Filter: filter,
		Group:  group,
	}
	var bb bytes.Buffer
	if err := tmpl.Execute(&bb, ctx); err != nil {
		return err
	}
	if strings.TrimSpace(bb.String()) != "" {
		return errors.New(bb.String())
	}
	return nil
}
