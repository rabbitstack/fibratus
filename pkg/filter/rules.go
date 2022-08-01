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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/atomic"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/funcmap"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
)

// maxOutstandingPartials determines the maximum number of partials per sequence index
const maxOutstandingPartials = 1000

var (
	excludeOrFilterMatches    = expvar.NewMap("filter.exclude.or.matches")
	excludeAndFilterMatches   = expvar.NewMap("filter.exclude.and.matches")
	includeOrFilterMatches    = expvar.NewMap("filter.include.or.matches")
	includeAndFilterMatches   = expvar.NewMap("filter.include.and.matches")
	filterGroupsCount         = expvar.NewInt("filter.groups.count")
	filterGroupsCountByPolicy = expvar.NewMap("filter.groups.count.policy")
	filtersCount              = expvar.NewInt("filter.filters.count")

	matchTransitionErrors = expvar.NewInt("sequence.match.transition.errors")
	partialsPerSequence   = expvar.NewMap("sequence.partials.count")
	partialExpirations    = expvar.NewMap("sequence.partial.expirations")

	ErrInvalidFilter = func(rule, group string, err error) error {
		return fmt.Errorf("invalid filter %q in %q group: %v", rule, group, err)
	}
	ErrInvalidPatternBinding = func(rule string) error {
		return fmt.Errorf("%q is the initial sequence rule and can't contain pattern bindings", rule)
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
	// sequenceExpiredState designates the state to which other
	// states transition when the sequence is expired
	sequenceExpiredState = fsm.State("expired")

	// transitions for match, cancel, reset, and expire triggers
	matchTransition  = fsm.Trigger("match")
	cancelTransition = fsm.Trigger("cancel")
	resetTransition  = fsm.Trigger("reset")
	expireTransition = fsm.Trigger("expire")
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
	name string

	// partials keeps the state of all matched events per rule index
	partials map[uint16][]*kevent.Kevent
	// matches stores only the event that matched
	// the upstream partials. These events will be propagated
	// in the rule action context
	matches map[uint16]*kevent.Kevent
	// bindingIndexes keeps a mapping of binding indexes per rule index
	bindingIndexes map[uint16]uint16

	fsm *fsm.StateMachine

	// rule to rule index mapping
	idxs          map[fsm.State]uint16
	maxSpans      map[fsm.State]time.Duration
	spanDeadlines map[fsm.State]*time.Timer
	inDeadline    atomic.Bool
	inExpired     bool
	initialState  fsm.State

	// matchedRules keeps the mapping between rule indexes and
	// their matches.
	matchedRules map[uint16]bool
}

func newSequenceState(name, initialState string) *sequenceState {
	ss := &sequenceState{
		name:           name,
		partials:       make(map[uint16][]*kevent.Kevent),
		matchedRules:   make(map[uint16]bool),
		matches:        make(map[uint16]*kevent.Kevent),
		idxs:           make(map[fsm.State]uint16),
		bindingIndexes: make(map[uint16]uint16),
		maxSpans:       make(map[fsm.State]time.Duration),
		spanDeadlines:  make(map[fsm.State]*time.Timer),
		initialState:   fsm.State(initialState),
		inDeadline:     atomic.MakeBool(false),
	}

	ss.initFSM(initialState)

	return ss
}

func (s *sequenceState) initFSM(initialState string) {
	s.fsm = fsm.NewStateMachine(initialState)
	s.fsm.OnTransitioned(func(ctx context.Context, transition fsm.Transition) {
		// schedule span deadline for the current state
		if dur, ok := s.maxSpans[s.currentState()]; ok {
			log.Debugf("scheduling max span deadline of %v for rule %s", dur, s.currentState())
			s.scheduleMaxSpanDeadline(s.currentState(), dur)
		}
		// if the sequence was deadlined/expired, we can disable the deadline
		// status when the first rule in the sequence is reevaluated
		if transition.Source == s.initialState && s.inDeadline.Load() {
			s.inDeadline.Store(false)
		}
		if transition.Source == s.initialState && s.inExpired {
			s.inExpired = false
		}
		// clear state in case of expire/deadline transitions
		if transition.Trigger == cancelTransition ||
			transition.Trigger == expireTransition {
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
			// save rule match
			s.matchedRules[s.idxs[transition.Source]] = true
		}
	})
}

func (s *sequenceState) matchTransition(rule string, kevt *kevent.Kevent) error {
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

func (s *sequenceState) addPartial(rule string, kevt *kevent.Kevent) {
	if len(s.partials[s.idxs[rule]]) > maxOutstandingPartials {
		log.Warnf("max partials encountered in sequence %s index %d. "+
			"Dropping incoming partial", s.name, s.idxs[rule])
		return
	}
	if len(s.bindingIndexes) > 0 {
		log.Debugf("adding partial to slot [%d] for rule %q: %s", s.idxs[rule], rule, kevt)
		partialsPerSequence.Add(s.name, 1)
		s.partials[s.idxs[rule]] = append(s.partials[s.idxs[rule]], kevt)
	}
}

func (s *sequenceState) addMatch(idx uint16, kevt *kevent.Kevent) {
	s.matches[idx] = kevt
}

func (s *sequenceState) getPartials(rule string) map[uint16][]*kevent.Kevent {
	i := s.idxs[rule] - 1
	// is this is the first rule in the sequence
	// return no partials
	if i == 0 {
		return nil
	}
	// next rules in the sequence contain partials
	// of their upstream rule. For example, if there
	// are two rules in the sequence, the partials map
	// will contain an index from rule 1 to all of its
	// partials
	if len(s.partials[i]) > 0 {
		partials := make(map[uint16][]*kevent.Kevent)
		partials[i] = s.partials[i]
		return partials
	}
	return nil
}

func (s *sequenceState) clear() {
	s.partials = make(map[uint16][]*kevent.Kevent)
	s.matches = make(map[uint16]*kevent.Kevent)
	s.matchedRules = make(map[uint16]bool)
	s.spanDeadlines = make(map[fsm.State]*time.Timer)
	partialsPerSequence.Delete(s.name)
}

// next determines whether the next rule in the
// sequence should be evaluated. The rule is evaluated
// if its upstream sequence rule produced a match and
// the sequence is not stuck in deadline or expired state.
func (s *sequenceState) next(i int) bool {
	// always evaluate the first rule in the sequence
	if i == 0 {
		return true
	}
	return s.matchedRules[uint16(i)] && !s.inDeadline.Load() && !s.inExpired
}

func (s *sequenceState) scheduleMaxSpanDeadline(rule fsm.State, maxSpan time.Duration) {
	t := time.AfterFunc(maxSpan, func() {
		inState, _ := s.fsm.IsInState(rule)
		if inState {
			log.Infof("max span of %v exceded for rule %s", maxSpan, rule)
			s.inDeadline.Store(true)
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
	if e.Type != ktypes.TerminateProcess {
		return false
	}
	canExpire := func(lhs, rhs *kevent.Kevent) bool {
		if lhs.Type != ktypes.CreateProcess {
			return false
		}
		p1, _ := lhs.Kparams.GetPid()
		p2, _ := rhs.Kparams.GetPid()
		return p1 == p2
	}
	for _, idx := range s.idxs {
		currentPartials := s.partials[idx]
		for i, e1 := range currentPartials {
			if !canExpire(e1, e) {
				continue
			}
			// if downstream rule didn't match, and it contains
			// a binding index to the previous rule in the sequence
			// whose condition is referencing a CreateProcess event
			// for which we just got the termination event, it is
			// safe to expire all pending partials and dispose
			// the state
			matched := s.matchedRules[idx+1]
			bindingIndex := s.bindingIndexes[idx+1]
			if !matched && bindingIndex == idx {
				log.Infof("removing process %s (%d) "+
					"from partials pertaining to sequence [%s]",
					e.Kparams.MustGetString(kparams.ProcessName),
					e.Kparams.MustGetPid(),
					s.name)
				s.partials[idx] = append(
					s.partials[idx][:i],
					s.partials[idx][i+1:]...)

				if len(s.partials[idx]) == 0 {
					log.Infof("%q sequence expired. All partials terminated", s.name)
					partialExpirations.Add(s.name, 1)
					s.inExpired = true
					err := s.expireTransition()
					if err != nil {
						s.inExpired = false
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
	}
	return false
}

func newFilterGroup(g config.FilterGroup, filters []compiledFilter) *filterGroup {
	return &filterGroup{group: g, filters: filters}
}

func newCompiledFilter(f Filter, filterConfig *config.FilterConfig) compiledFilter {
	return compiledFilter{config: filterConfig, filter: f}
}

// run execute the filter and returns the matching partial index along with
// the partial event that produced a match.
func (f compiledFilter) run(kevt *kevent.Kevent, i uint16, partials map[uint16][]*kevent.Kevent) (bool, uint16, *kevent.Kevent) {
	if len(partials) > 0 {
		return f.filter.RunPartials(kevt, partials)
	}
	return f.filter.Run(kevt), i, kevt
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

func (r *Rules) hasSequencePolicy() bool { return len(r.sequenceGroups) > 0 }

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
		if group.IsDisabled() {
			log.Warnf("rule group [%s] disabled", group.Name)
			continue
		}
		log.Infof("loading rule group [%s]", group.Name)
		rules := append(group.Rules, group.FromStrings...)
		if group.Policy != config.SequencePolicy &&
			group.Action != "" {
			return fmt.Errorf("%s: only sequence policies can have top level actions", group.Name)
		}
		if group.Policy == config.SequencePolicy &&
			len(rules) <= 1 {
			return fmt.Errorf("%s: policy requires at least two rules", group.Name)
		}

		filterGroupsCount.Add(1)
		filterGroupsCountByPolicy.Add(group.Policy.String(), 1)

		// compile filters and populate the groups. Additionally, for
		// sequence policies we have to configure the FSM states and
		// transitions.
		if len(rules) == 0 {
			panic("got empty rules")
		}
		initialState := rules[0].Name
		seqState := newSequenceState(group.Name, initialState)
		filters := make([]compiledFilter, 0, len(rules))

		for i, filterConfig := range rules {
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
				bindingID, ok := f.BindingIndex()
				if ok {
					if i == 0 {
						return ErrInvalidPatternBinding(rule)
					}
					seqState.bindingIndexes[uint16(i+1)] = bindingID
				}
				// set maximum span deadline
				if filterConfig.MaxSpan != 0 {
					seqState.maxSpans[rule] = filterConfig.MaxSpan
				}
				if i >= len(rules)-1 {
					seqState.fsm.Configure(rule).
						Permit(matchTransition, sequenceTerminalState).
						Permit(cancelTransition, sequenceDeadlineState).
						Permit(expireTransition, sequenceExpiredState)
				} else {
					seqState.fsm.Configure(rule).
						Permit(matchTransition, rules[i+1].Name).
						Permit(cancelTransition, sequenceDeadlineState).
						Permit(expireTransition, sequenceExpiredState)
				}
			}
			filters = append(filters, newCompiledFilter(f, filterConfig))
			filtersCount.Add(1)
		}

		// initialize filter groups
		fg := newFilterGroup(group, filters)

		switch group.Policy {
		case config.ExcludePolicy, config.IncludePolicy:
			// compute the hash depending on whether the type or category
			// is given in the group selector. For sequence group policies
			// we don't really care about the selector because these groups
			// must attract all event types. In this case the hash is the
			// filter group hash.
			hash := group.Selector.Hash()
			r.filterGroups[hash] = append(r.filterGroups[hash], fg)
		case config.SequencePolicy:
			// configure reset transitions that are triggered
			// when the final state is reached of when a deadline
			// or sequence expiration happens
			seqState.fsm.Configure(sequenceTerminalState).Permit(resetTransition, initialState)
			seqState.fsm.Configure(sequenceDeadlineState).Permit(resetTransition, initialState)
			seqState.fsm.Configure(sequenceExpiredState).Permit(resetTransition, initialState)

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
	if len(r.filterGroups) == 0 && len(r.sequenceGroups) == 0 {
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

	if !groups.hasIncludePolicy(kevt) && !r.hasSequencePolicy() {
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
			// if the sequence expired we'll not keep evaluating
			if seqState.expire(kevt) {
				return false
			}
			for i, f := range g.filters {
				if !seqState.next(i) {
					continue
				}
				rule := f.config.Name
				ok, idx, e := f.run(kevt, uint16(i+1), seqState.getPartials(rule))
				if ok {
					seqState.addPartial(rule, kevt)
					err := seqState.matchTransition(rule, kevt)
					if err != nil {
						matchTransitionErrors.Add(1)
						log.Warnf("match transition: %v", err)
					}
					seqState.addMatch(uint16(i+1), kevt)
					seqState.addMatch(idx, e)
				}
			}
			done := seqState.isTerminalState()
			if done {
				log.Debugf("rule group [%s] matched", g.group.Name)
				// this is the event that triggered the group match
				kevt.AddMeta(kevent.RuleGroupKey, g.group.Name)
				err := runFilterAction(nil, seqState.matches, g.group, nil)
				if err != nil {
					log.Warnf("unable to execute %q sequence action: %v", g.group.Name, err)
				}
				seqState.clear()
			}
			return done
		}
		var andMatched bool
		// process include/exclude filter groups. Each of them
		// may have `or` or `and` relation types to promote the
		// group upon first match or either all rules in the group
		// need to match
		for i, f := range g.filters {
			ok, _, _ := f.run(kevt, uint16(i+1), nil)

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
						log.Debugf("rule [%s] in group [%s] matched", f.config.Name, g.group.Name)
						err := runFilterAction(kevt, nil, g.group, f.config)
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
					log.Debugf("rule [%s] in group [%s] matched", f.config.Name, g.group.Name)
					err := runFilterAction(kevt, nil, g.group, f.config)
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
	Kevts  map[string]*kevent.Kevent
	Filter *config.FilterConfig
	Group  config.FilterGroup
}

// runFilterAction executes the template associated with the filter
// that has produced a match in one of the include groups.
func runFilterAction(
	kevt *kevent.Kevent,
	kevts map[uint16]*kevent.Kevent,
	group config.FilterGroup,
	filter *config.FilterConfig,
) error {
	if (filter != nil && filter.Action == "") && group.Action == "" {
		return nil
	}
	var action []byte
	var err error
	if group.Policy == config.SequencePolicy {
		action, err = base64.StdEncoding.DecodeString(group.Action)
	} else {
		if filter == nil {
			panic("filter shouldn't be nil")
		}
		action, err = base64.StdEncoding.DecodeString(filter.Action)
	}
	if err != nil {
		return fmt.Errorf("corrupted filter/group action: %v", err)
	}

	fmap := funcmap.New()
	funcmap.InitFuncs(fmap)
	tmpl, err := template.New(group.Name).Funcs(fmap).Parse(string(action))
	if err != nil {
		return err
	}

	matches := make(map[string]*kevent.Kevent, len(kevts))
	for k, v := range kevts {
		matches["k"+strconv.Itoa(int(k))] = v
	}

	ctx := &ActionContext{
		Kevt:   kevt,
		Kevts:  matches,
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
