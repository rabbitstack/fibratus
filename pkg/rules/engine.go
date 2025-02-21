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
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/action"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	log "github.com/sirupsen/logrus"
	"time"
)

var (
	// sequenceGcInterval determines how often sequence GC kicks in
	sequenceGcInterval = time.Minute

	filterMatches         = expvar.NewMap("filter.matches")
	matchTransitionErrors = expvar.NewInt("sequence.match.transition.errors")

	ErrRuleAction = func(rule string, err error) error {
		return fmt.Errorf("fail to execute action for %q rule: %v", rule, err)
	}
)

// Engine stores the compiled filter exprs
// and for each incoming event, it applies
// the corresponding filter to the event.
// If the filter rule has an action, the
// former is executed when the rule fires.
type Engine struct {
	filters map[uint32][]*compiledFilter
	config  *config.Config
	psnap   ps.Snapshotter

	matches   []*ruleMatch
	sequences []*sequenceState

	scavenger *time.Ticker

	compiler *compiler
}

type ruleMatch struct {
	ctx *config.ActionContext
}

type compiledFilter struct {
	filter filter.Filter
	config *config.FilterConfig
	ss     *sequenceState
}

func newCompiledFilter(f filter.Filter, c *config.FilterConfig, ss *sequenceState) *compiledFilter {
	return &compiledFilter{filter: f, config: c, ss: ss}
}

// isScoped determines if this filter is scoped, i.e. it has the event name or category
// conditions.
func (f *compiledFilter) isScoped() bool {
	for name := range f.filter.GetStringFields() {
		if name == fields.KevtName || name == fields.KevtCategory {
			return true
		}
	}
	return false
}

func (f *compiledFilter) isSequence() bool {
	return f.ss != nil
}

func (f *compiledFilter) run(e *kevent.Kevent) bool {
	if f.ss != nil {
		return f.ss.runSequence(e)
	}
	return f.filter.Run(e)
}

// NewEngine builds a fresh rules engine instance.
func NewEngine(psnap ps.Snapshotter, config *config.Config) *Engine {
	e := &Engine{
		filters:   make(map[uint32][]*compiledFilter),
		matches:   make([]*ruleMatch, 0),
		sequences: make([]*sequenceState, 0),
		psnap:     psnap,
		config:    config,
		scavenger: time.NewTicker(sequenceGcInterval),
		compiler:  newCompiler(psnap, config),
	}

	go e.gcSequences()

	return e
}

func (e *Engine) gcSequences() {
	for {
		<-e.scavenger.C
		for _, seq := range e.sequences {
			seq.gc()
		}
	}
}

// Compile loads macros and rules from the ruleset.
func (e *Engine) Compile() (*config.RulesCompileResult, error) {
	filters, rs, err := e.compiler.compile()
	if err != nil {
		return nil, err
	}

	for c, f := range filters {
		var ss *sequenceState
		if f.IsSequence() {
			ss = newSequenceState(f, c)
		}
		fltr := newCompiledFilter(f, c, ss)
		if ss != nil {
			// store the sequences in engine
			// for more convenient tracking
			e.sequences = append(e.sequences, ss)
		}
		// traverse all event name or category fields and determine
		// the event type from the filter field name expression.
		// We end up with a map of rules indexed by event name
		// or event category hash
		if !fltr.isScoped() {
			log.Warnf("%q rule doesn't have "+
				"event type or event category condition! "+
				"This rule is being discarded by "+
				"the engine. Please consider narrowing the "+
				"scope of the rule by including the `kevt.name` "+
				"or `kevt.category` condition",
				c.Name)
			continue
		}
		// map the filter to the hash of its event type/category
		for name, values := range f.GetStringFields() {
			for _, v := range values {
				if name == fields.KevtName || name == fields.KevtCategory {
					hash := hashers.FnvUint32([]byte(v))
					e.filters[hash] = append(e.filters[hash], fltr)
				}
			}
		}
	}

	return rs, nil
}

func (*Engine) CanEnqueue() bool { return true }

func (e *Engine) ProcessEvent(evt *kevent.Kevent) (bool, error) {
	if len(e.filters) == 0 {
		return true, nil
	}
	if evt.IsTerminateProcess() {
		// expire all sequences if the
		// process referenced in any
		// partials has terminated
		for _, seq := range e.sequences {
			seq.expire(evt)
		}
	}
	filters := e.findFilters(evt)
	for _, f := range filters {
		match := f.run(evt)
		if match && !f.isSequence() {
			// transition sequence states since a match
			// in a simple rule could trigger multiple
			// matches in sequence rules
			for _, seq := range filters {
				if !seq.isSequence() {
					continue
				}
				if seq.run(evt) {
					e.appendMatch(f.config, f.ss.events()...)
					f.ss.clearLocked()
					err := e.processActions()
					if err != nil {
						log.Errorf("unable to execute rule action: %v", err)
					}
				}
			}
		}
		if match {
			if f.isSequence() {
				e.appendMatch(f.config, f.ss.events()...)
				f.ss.clearLocked()
			} else {
				e.appendMatch(f.config, evt)
			}
			err := e.processActions()
			if err != nil {
				log.Errorf("unable to execute rule action: %v", err)
			}
			return true, nil
		}
	}
	return false, nil
}

// findFilters collects all compiled filters for a
// particular event type or category. If no filters
// are found, the event is not asserted against the
// ruleset.
func (e *Engine) findFilters(evt *kevent.Kevent) []*compiledFilter {
	return append(e.filters[evt.Type.Hash()], e.filters[evt.Category.Hash()]...)
}

// processActions executes rule actions
// on behalf of rule matches. Actions are
// categorized into implicit and explicit
// actions.
// Sending an alert is an implicit action
// carried out each time there is a rule
// match. Other actions are executed if
// defined in the rule definition.
func (e *Engine) processActions() error {
	defer e.clearMatches()
	for _, m := range e.matches {
		f, evts := m.ctx.Filter, m.ctx.Events
		filterMatches.Add(f.Name, 1)
		log.Debugf("[%s] rule matched", f.Name)
		err := action.Emit(m.ctx, f.Name, filter.InterpolateFields(f.Output, evts), f.Severity, f.Tags)
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

func (e *Engine) appendMatch(f *config.FilterConfig, evts ...*kevent.Kevent) {
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
	e.matches = append(e.matches, &ruleMatch{ctx: ctx})
}

func (e *Engine) clearMatches() {
	e.matches = make([]*ruleMatch, 0)
}
