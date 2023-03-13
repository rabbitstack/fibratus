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
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"net"
	"sort"

	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/atomic"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
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
		return fmt.Errorf("syntax error in rule %q located in %q group: \n%v", rule, group, err)
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
	filterGroups    map[uint32]filterGroups
	excludePolicies bool
	config          *config.Config
}

type filterGroup struct {
	group   config.FilterGroup
	filters []*compiledFilter
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
	// matches stores only the event that matched
	// the upstream partials. These events will be propagated
	// in the rule action context
	matches map[uint16]*kevent.Kevent

	fsm *fsm.StateMachine

	// rule to rule index mapping. Indices start at 1
	idxs          map[fsm.State]uint16
	spanDeadlines map[fsm.State]*time.Timer
	inDeadline    atomic.Bool
	inExpired     bool
	initialState  fsm.State

	// matchedRules keeps the mapping between rule indexes and
	// their matches.
	matchedRules map[uint16]bool
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
	i := s.idxs[rule]
	if len(s.partials[i]) > maxOutstandingPartials {
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
	log.Debugf("adding partial to slot [%d] for rule %q: %s", i, rule, kevt)
	partialsPerSequence.Add(s.name, 1)
	s.partials[i] = append(s.partials[i], kevt)
}

func (s *sequenceState) isAfter(rule string, kevt *kevent.Kevent) bool {
	i := s.idxs[rule]
	if len(s.partials[i]) == 0 {
		return true
	}
	return kevt.Timestamp.After(s.partials[i][len(s.partials[i])-1].Timestamp)
}

func (s *sequenceState) clear() {
	s.partials = make(map[uint16][]*kevent.Kevent)
	s.matches = make(map[uint16]*kevent.Kevent)
	s.matchedRules = make(map[uint16]bool)
	s.spanDeadlines = make(map[fsm.State]*time.Timer)
	partialsPerSequence.Delete(s.name)
}

func compareSeqJoin(s1, s2 any) bool {
	if s1 == nil || s2 == nil {
		return false
	}
	switch v := s1.(type) {
	case string:
		s, ok := s2.(string)
		if !ok {
			return false
		}
		return strings.EqualFold(v, s)
	case uint8:
		n, ok := s2.(uint8)
		if !ok {
			return false
		}
		return v == n
	case uint16:
		n, ok := s2.(uint16)
		if !ok {
			return false
		}
		return v == n
	case uint32:
		n, ok := s2.(uint32)
		if !ok {
			return false
		}
		return v == n
	case uint64:
		n, ok := s2.(uint64)
		if !ok {
			return false
		}
		return v == n
	case int:
		n, ok := s2.(int)
		if !ok {
			return false
		}
		return v == n
	case uint:
		n, ok := s2.(uint)
		if !ok {
			return false
		}
		return v == n
	case net.IP:
		ip, ok := s2.(net.IP)
		if !ok {
			return false
		}
		return v.Equal(ip)
	}
	return false
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
	if !e.IsTerminateProcess() {
		return false
	}
	canExpire := func(lhs, rhs *kevent.Kevent) bool {
		if lhs.Type == ktypes.CreateProcess {
			p1, _ := lhs.Kparams.GetPid()
			p2, _ := rhs.Kparams.GetPid()
			return p1 == p2
		}
		return lhs.PID == rhs.PID
	}
	for _, idx := range s.idxs {
		for i := len(s.partials[idx]) - 1; i >= 0; i-- {
			if len(s.partials[idx]) > 0 && !canExpire(s.partials[idx][i], e) {
				continue
			}
			// if downstream rule didn't match, and the prev condition
			// is referencing a CreateProcess event for which we just
			// got the termination event, it is safe to expire all pending
			// partials and dispose the state
			matched := s.matchedRules[idx+1]
			if !matched {
				log.Debugf("removing event originated from %s (%d) "+
					"in partials pertaining to sequence [%s]",
					e.Kparams.MustGetString(kparams.ProcessName),
					e.Kparams.MustGetPid(),
					s.name)
				// remove partial event from the corresponding slot
				s.partials[idx] = append(
					s.partials[idx][:i],
					s.partials[idx][i+1:]...)
				partialsPerSequence.Add(s.name, -1)

				if len(s.partials[idx]) == 0 {
					log.Infof("%q sequence expired. All partials retracted", s.name)
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

func newFilterGroup(g config.FilterGroup, filters []*compiledFilter) *filterGroup {
	return &filterGroup{group: g, filters: filters}
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
func (f compiledFilter) run(kevt *kevent.Kevent, i uint16) bool {
	if f.ss != nil {
		return f.filter.RunSequence(kevt, i, f.ss.partials)
	}
	return f.filter.Run(kevt)
}

type filterGroups []*filterGroup

func (groups filterGroups) hasIncludePolicy() bool {
	for _, g := range groups {
		if g.group.Policy == config.IncludePolicy {
			return true
		}
	}
	return false
}

func (r *Rules) isGroupMapped(scopeHash, groupHash uint32) bool {
	for h, groups := range r.filterGroups {
		for _, g := range groups {
			if h == scopeHash && g.group.Hash() == groupHash {
				return true
			}
		}
	}
	return false
}

// NewRules produces a fresh rules instance.
func NewRules(c *config.Config) Rules {
	rules := Rules{
		filterGroups: make(map[uint32]filterGroups),
		config:       c,
	}
	return rules
}

func expr(c *config.FilterConfig) string {
	if c.Condition != "" {
		return c.Condition
	}
	return c.Def
}

// Compile loads macros and rule groups from all
// indicated resources and creates the rules for
// each filter group. It also sets up the state
// machine transitions for sequence rule group policies.
func (r *Rules) Compile() error {
	if err := r.config.Filters.LoadMacros(); err != nil {
		return err
	}
	groups, err := r.config.Filters.LoadGroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group.IsDisabled() {
			log.Warnf("rule group [%s] disabled", group.Name)
			continue
		}
		if group.Policy == config.ExcludePolicy {
			r.excludePolicies = true
		}
		filterGroupsCount.Add(1)
		filterGroupsCountByPolicy.Add(group.Policy.String(), 1)
		log.Infof("loading rule group [%s] with %q policy", group.Name, group.Policy)

		// compile filters and populate the groups. Additionally, for
		// sequence rules we have to configure the FSM states and
		// transitions
		rules := append(group.Rules, group.FromStrings...)
		filters := make([]*compiledFilter, 0, len(rules))

		for _, filterConfig := range rules {
			rule := filterConfig.Name
			f := New(expr(filterConfig), r.config)
			err := f.Compile()
			if err != nil {
				return ErrInvalidFilter(rule, group.Name, err)
			}
			for _, field := range f.GetFields() {
				deprecated, d := fields.IsDeprecated(field)
				if deprecated {
					log.Warnf("%s rule uses the [%s] field which "+
						"was deprecated starting from version %s. "+
						"Please consider migrating to [%s] field "+
						"because [%s] will be removed in future versions.",
						rule, field, d.Since, d.Field, field)
				}
			}
			var seqState *sequenceState
			if f.IsSequence() {
				seq := f.GetSequence()
				expressions := seq.Expressions
				if len(expressions) == 0 {
					panic("expressions cannot be empty")
				}
				initialState := expressions[0].Expr.String()
				seqState = newSequenceState(group.Name, initialState, seq.MaxSpan)
				// setup finite state machine states. The last rule
				// in the sequence transitions to the terminal state
				// if all rules match
				for i, expr := range expressions {
					n := expr.Expr.String()
					seqState.idxs[n] = uint16(i + 1)
					if i >= len(expressions)-1 {
						seqState.fsm.Configure(n).
							Permit(matchTransition, sequenceTerminalState).
							Permit(cancelTransition, sequenceDeadlineState).
							Permit(expireTransition, sequenceExpiredState)
					} else {
						seqState.fsm.Configure(n).
							Permit(matchTransition, expressions[i+1].Expr.String()).
							Permit(cancelTransition, sequenceDeadlineState).
							Permit(expireTransition, sequenceExpiredState)
					}
				}
				// configure reset transitions that are triggered
				// when the final state is reached of when a deadline
				// or sequence expiration happens
				seqState.fsm.Configure(sequenceTerminalState).Permit(resetTransition, initialState)
				seqState.fsm.Configure(sequenceDeadlineState).Permit(resetTransition, initialState)
				seqState.fsm.Configure(sequenceExpiredState).Permit(resetTransition, initialState)
			}
			filtersCount.Add(1)
			filters = append(filters, newCompiledFilter(f, filterConfig, seqState))
		}

		g := newFilterGroup(group, filters)

		// traverse all filters in the groups and determine
		// the event type from the filter field name expression.
		// We end up with a map of rule groups indexed by event name
		// or event category hash which is used to collect all groups
		// for the inbound event
		for _, f := range filters {
			if !f.isScoped() {
				log.Warnf("%q rule in %q group doesn't have event type or event category condition! "+
					"This may lead to rule being discarded by the engine. Please consider "+
					"narrowing the scope of this rule by including the `kevt.name` "+
					"or `kevt.category` condition",
					f.config.Name, g.group.Name)
				continue
			}
			for name, values := range f.filter.GetStringFields() {
				for _, v := range values {
					if name == fields.KevtName || name == fields.KevtCategory {
						hash := hashers.FnvUint32([]byte(v))
						if r.isGroupMapped(hash, g.group.Hash()) {
							continue
						}
						r.filterGroups[hash] = append(r.filterGroups[hash], g)
					}
				}
			}
		}
	}
	return nil
}

func (r *Rules) findGroups(kevt *kevent.Kevent) filterGroups {
	groups1 := r.filterGroups[kevt.Type.Hash()]
	groups2 := r.filterGroups[kevt.Category.Hash()]
	if groups1 == nil && groups2 == nil {
		return nil
	}
	return append(groups1, groups2...)
}

func (r *Rules) Fire(kevt *kevent.Kevent) bool {
	// no rules were loaded into the engine in
	// which the event is forwarded to the aggregator
	// unless the CLI filter decides otherwise
	if len(r.filterGroups) == 0 {
		return true
	}
	// find rule groups for a particular event type
	// or category. If no rule groups are found we
	// drop the event
	groups := r.findGroups(kevt)
	if len(groups) == 0 {
		return false
	}
	// exclude policies take precedence over
	// groups with include policies, so we first
	// evaluate those. If no filter matches occur,
	// we let pass the event but only if there are
	// no groups with include policy
	if r.excludePolicies {
		if r.runRules(groups, config.ExcludePolicy, kevt) {
			return false
		}
		if !groups.hasIncludePolicy() {
			return true
		}
	}
	// run include policy rules. At this point none of
	// the groups with exclude policies got matched
	return r.runRules(groups, config.IncludePolicy, kevt)
}

func (r *Rules) runSequence(kevt *kevent.Kevent, f *compiledFilter) bool {
	seq := f.filter.GetSequence()
	for i, expr := range seq.Expressions {
		// only try to evaluate the expression
		// if upstream expressions have matched
		if !f.ss.next(i) {
			continue
		}
		// prevent running the filter if the expression
		// can't be matched against the current event
		if !expr.IsEvaluable(kevt) {
			continue
		}
		rule := expr.Expr.String()
		matches := f.run(kevt, uint16(i))
		// append the partial and transition state machine
		if matches && f.ss.isAfter(rule, kevt) {
			f.ss.addPartial(rule, kevt)
			err := f.ss.matchTransition(rule, kevt)
			if err != nil {
				matchTransitionErrors.Add(1)
				log.Warnf("match transition failure: %v", err)
			}
		}
	}
	// if both the terminal state is reached and the partials
	// in the sequence state could be joined by the specified
	// field(s), the rule has matched successfully, and we can
	// collect all events involved in the rule match
	isTerminal := f.ss.isTerminalState()
	if isTerminal {
		nseqs := uint16(len(f.ss.partials))
		for i := uint16(1); i < nseqs+1; i++ {
			for _, outer := range f.ss.partials[i] {
				for _, inner := range f.ss.partials[i+1] {
					if compareSeqJoin(outer.SequenceBy(), inner.SequenceBy()) {
						f.ss.matches[i], f.ss.matches[i+1] = outer, inner
					}
				}
			}
		}
	}
	return isTerminal
}

func (r *Rules) runRules(groups filterGroups, policy config.FilterGroupPolicy, kevt *kevent.Kevent) bool {
nextGroup:
	for _, g := range groups {
		if g.group.Policy != policy {
			continue
		}
		var andMatched bool
		// process include/exclude filter groups. Each of them
		// may have `or` or `and` relation types to promote the
		// group upon first match or either all rules in the group
		// need to match
		for i, f := range g.filters {
			var match bool
			if f.ss != nil {
				if f.ss.expire(kevt) {
					continue
				}
				match = r.runSequence(kevt, f)
			} else {
				match = f.run(kevt, uint16(i))
				if match {
					// transition sequence states since a match
					// in a simple rule could trigger multiple
					// matches in sequence rules
					for _, f := range g.filters {
						if !f.filter.IsSequence() || f.ss == nil {
							continue
						}
						if f.ss.expire(kevt) {
							continue
						}
						if r.runSequence(kevt, f) {
							kevt.AddMeta(kevent.RuleNameKey, f.config.Name)
							log.Debugf("rule [%s] in group [%s] matched", f.config.Name, g.group.Name)
							err := runFilterAction(nil, f.ss.matches, g.group, f.config)
							if err != nil {
								log.Warnf("unable to execute %q rule action: %v", f.config.Name, err)
							}
							f.ss.clear()
						}
					}
				}
			}
			switch g.group.Policy {
			case config.ExcludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if match {
						excludeOrFilterMatches.Add(f.config.Name, 1)
						return true
					}
				case config.AndRelation:
					if !match {
						// jump to the next exclude group
						continue nextGroup
					}
					andMatched = true
				}
			case config.IncludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if match {
						includeOrFilterMatches.Add(f.config.Name, 1)
						log.Debugf("rule [%s] in group [%s] matched", f.config.Name, g.group.Name)
						// attach rule and group meta
						kevt.AddMeta(kevent.RuleNameKey, f.config.Name)
						kevt.AddMeta(kevent.RuleGroupKey, g.group.Name)
						for k, v := range g.group.Labels {
							kevt.AddMeta(kevent.MetadataKey(k), v)
						}
						var err error
						if f.ss != nil {
							err = runFilterAction(nil, f.ss.matches, g.group, f.config)
							f.ss.clear()
						} else {
							err = runFilterAction(kevt, nil, g.group, f.config)
						}
						if err != nil {
							log.Warnf("unable to execute %q rule action: %v", f.config.Name, err)
						}
						return true
					}
				case config.AndRelation:
					if !match {
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
					var err error
					if f.ss != nil {
						err = runFilterAction(nil, f.ss.matches, g.group, f.config)
						f.ss.clear()
					} else {
						err = runFilterAction(kevt, nil, g.group, f.config)
					}
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

// runFilterAction executes the template associated with the filter
// that has produced a match in one of the rule groups with include
// policy.
func runFilterAction(
	kevt *kevent.Kevent,
	kevts map[uint16]*kevent.Kevent,
	group config.FilterGroup,
	filter *config.FilterConfig,
) error {
	if filter != nil && filter.Action == "" {
		return nil
	}
	actionBlock, err := base64.StdEncoding.DecodeString(filter.Action)
	if err != nil {
		return fmt.Errorf("corrupted filter/group action: %v", err)
	}

	events := make([]*kevent.Kevent, 0)
	matches := make(map[string]*kevent.Kevent, len(kevts))
	if kevt != nil {
		events = append(events, kevt)
	} else {
		for k, kevt := range kevts {
			events = append(events, kevt)
			matches["k"+strconv.Itoa(int(k))] = kevt
		}
		sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	}

	fmap := NewFuncMap()
	InitFuncs(fmap)
	tmpl, err := template.New(group.Name).Funcs(fmap).Parse(string(actionBlock))
	if err != nil {
		return err
	}

	ctx := &config.ActionContext{
		Kevt:   kevt,
		Kevts:  matches,
		Events: events,
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
