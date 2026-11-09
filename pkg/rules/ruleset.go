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
	"slices"
	"sync"

	semver "github.com/hashicorp/go-version"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/macro"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	log "github.com/sirupsen/logrus"
)

// rulesCount is the number of rules in the current rule set.
var rulesCount = expvar.NewInt("ruleset.rules.count")

var (
	// ErrInvalidRule indicates the rule has a syntax error.
	ErrInvalidRule = func(rule string, err error) error {
		return fmt.Errorf("syntax error in rule %q: \n%v", rule, err)
	}
	// ErrIncompatibleRule indicates the rule requires a newer engine.
	ErrIncompatibleRule = func(rule, v string) error {
		return fmt.Errorf("rule %q needs engine version [%s] but current version is [%s]", rule, v, version.Get())
	}
	// ErrMalformedMinEngineVer indicates the minimum engine version is not a semantic version.
	ErrMalformedMinEngineVer = func(rule, v string, err error) error {
		return fmt.Errorf("rule %q has a malformed minimum engine version: %s: %v", rule, v, err)
	}
	// ErrUnknownEventName indicates the rule references an unknown event name.
	ErrUnknownEventName = func(rule, name string) error {
		return fmt.Errorf("rule %s references an invalid event name %q in the evt.name field", rule, name)
	}
	// ErrUnknownCategoryName indicates the rule references an unknown event category.
	ErrUnknownCategoryName = func(rule, name string) error {
		return fmt.Errorf("rule %s references an invalid event category %q in the evt.category field", rule, name)
	}
)

// RuleMatch is the rule that matched along with the events that triggered it.
// For simple rules there is a single event. For sequences, the events are the
// ordered events of all sequence steps.
type RuleMatch struct {
	Rule   *Rule
	Events []*event.Event
}

// RuleSetListener describes the methods that the component has to satisfy
// to be notified of an events on the rule set.
type RuleSetListener interface {
	// RuleMatch is called when the rule matches. The events are the single
	// event for simple rules, or the ordered events of all steps for sequences.
	// The listener returns false to stop the notification of the remaining listeners.
	RuleMatch(rule *Rule, events []*event.Event) bool
}

// Option customizes the rule set.
type Option func(*RuleSet)

// WithMatchAll sets the match all strategy. If it is enabled, a single event
// can trigger multiple rules. Otherwise, the evaluation stops at the first match.
func WithMatchAll(matchAll bool) Option {
	return func(rs *RuleSet) { rs.matchAll = matchAll }
}

// WithApproverCaps sets the event attributes the event source can resolve
// before it materializes the events. The approvers are derived from them.
func WithApproverCaps(caps ApproverCaps) Option {
	return func(rs *RuleSet) { rs.approverCaps = caps }
}

// RuleSet is the central piece of the rule engine. It stores all the rules
// compiled from the policies, indexes them by the event type they are
// interested in, and evaluates the events against them. The listeners are
// notified of every rule that matches.
//
// The rule set is populated while it is built, by adding the macros and then
// the rules. Afterwards, it is only read, so reloading rules means building a
// new rule set and replacing the old one. The only state that changes while
// evaluating the events is the state that sequences accumulate, which is
// guarded by the sequences.
type RuleSet struct {
	matchAll     bool
	approverCaps ApproverCaps

	policies  []*policy.Policy
	macroDefs []*policy.MacroDef
	macros    *macro.Store

	// rules contains all the rules in the order they were loaded
	rules []*Rule
	byID  map[policy.RuleID]*Rule

	policyLoader *policy.Loader

	// ruleBuckets contains rules indexed by the event type
	ruleBuckets [event.MaxEvent]*RuleBucket

	discarded []DiscardedRule

	listenersLock sync.RWMutex
	listeners     []RuleSetListener

	// report is computed lazily, and discarded when the rules change
	reportMu sync.Mutex
	report   *RuleSetReport
}

// NewRuleSet returns a new ruleset for the specified data model
func NewRuleSet(opts ...Option) *RuleSet {
	logger := log.OrNullLogger(opts.Logger)

	if evalOpts.MacroStore == nil {
		evalOpts.WithMacroStore(&eval.MacroStore{})
	}

	if evalOpts.VariableStore == nil {
		evalOpts.WithVariableStore(&eval.VariableStore{})
	}

	return &RuleSet{
		opts:             opts,
	}
}

// NewRuleSet builds the rule set from the policies. The macros of all
// policies are shared by the rules of all policies. It either returns the
// rule set with all rules compiled or the error that describes every rule
// that couldn't be compiled. In the latter case, there is no partial rule
// set, so the caller can keep using the previous one.
// func NewRuleSet(policies []*policy.Policy, opts ...Option) (*RuleSet, error) {
// 	rs := NewEmptyRuleSet(opts...)
// 	rs.policies = policies

// 	var macros []*policy.MacroDef
// 	for _, p := range policies {
// 		if !p.IsBehaviour() {
// 			log.Debugf("skipping %q policy of %s type", p.Name, p.Type)
// 			continue
// 		}
// 		macros = append(macros, p.Macros...)
// 	}
// 	if err := rs.AddMacros(macros); err != nil {
// 		return nil, err
// 	}

// 	var errs []error
// 	for _, p := range policies {
// 		if !p.IsBehaviour() {
// 			continue
// 		}
// 		for _, def := range p.Rules {
// 			if def.IsDisabled() {
// 				log.Warnf("[%s] rule is disabled", def.Name)
// 				continue
// 			}
// 			if err := rs.AddRule(def, p.Source); err != nil {
// 				errs = append(errs, err)
// 			}
// 		}
// 	}
// 	if len(errs) > 0 {
// 		return nil, multierror.Wrap(errs...)
// 	}

// 	rulesCount.Set(int64(len(rs.rules)))

// 	return rs, nil
// }


// func NewEmptyRuleSet(opts ...Option) *RuleSet {
// 	rs := &RuleSet{
// 		byID:         make(map[policy.RuleID]*Rule),
// 		types:        make(map[event.Type]*RuleBucket),
// 		approverCaps: DefaultApproverCaps(),
// 	}
// 	rs.macros, _ = macro.NewStore()
// 	for _, opt := range opts {
// 		opt(rs)
// 	}
// 	return rs

// AddMacros adds the macros to the rule set. The macros have to be added before
// the rules that reference them. If any macro is invalid, e.g. duplicate or
// involved in a cycle, no macro is added.
func (rs *RuleSet) AddMacros(macros []*policy.MacroDef) error {
	defs := append(slices.Clone(rs.macroDefs), macros...)
	store, err := macro.NewStore(defs...)
	if err != nil {
		return err
	}
	rs.macroDefs, rs.macros = defs, store
	return nil
}

// AddMacro adds the macro to the rule set.
func (rs *RuleSet) AddMacro(m *policy.MacroDef) error {
	return rs.AddMacros([]*policy.MacroDef{m})
}

// AddRules adds the rules to the rule set. The rules that can't be added are
// reported in the returned error, but they don't prevent the other rules from
// being added.
func (rs *RuleSet) AddRules(rules []*policy.RuleDef, source string) error {
	var errs []error
	for _, rule := range rules {
		if err := rs.AddRule(rule, source); err != nil {
			errs = append(errs, err)
		}
	}
	return multierror.Wrap(errs...)
}

// AddRule compiles the rule definition and indexes the rule. The rules that
// aren't scoped by the event type are discarded with a warning, and are
// listed in the report.
func (rs *RuleSet) AddRule(ruleDef *policy.RuleDef, source string) error {
	if ruleDef.IsDisabled() {
		return nil
	}

	if r, ok := rs.byID[ruleDef.ID]; ok {
		return fmt.Errorf("%q rule uses duplicate id %s (already used by %q)", ruleDef.Name, ruleDef.ID, r.Name)
	}

	if err := checkEngineVersion(ruleDef); err != nil {
		return err
	}

	rule, err := NewRule(ruleDef, rs.macros)
	if err != nil {
		return ErrInvalidRule(ruleDef.Name, err)
	}
	rule.Source = source

	if err := validateEventRefs(rule); err != nil {
		return err
	}

	// output the warnings for deprecated fields
	for _, field := range rule.evaluator.GetFields() {
		if deprecated, d := fields.IsDeprecated(field.Name); deprecated {
			log.Warnf("%s rule uses the [%s] field which "+
				"was deprecated starting from version %s. "+
				"Please consider migrating to %s field(s) "+
				"because [%s] will be removed in future versions.",
				ruleDef.Name, field.Name, d.Since, d.Fields, field.Name)
		}
	}

	scope := rule.scope
	if scope == nil {
		log.Warnf("%q rule doesn't have the event type condition! "+
			"This rule is being discarded by the engine. Please consider "+
			"narrowing the scope of the rule by including the `evt.name` "+
			"condition. Rules can't be scoped by the event category",
			ruleDef.Name)
		rs.discard(ruleDef.Name, source, "the rule is not scoped by the event type")
		return nil
	}
	if scope.IsEmpty() {
		log.Warnf("%q rule can never match because its event type "+
			"conditions are contradicting. This rule is being "+
			"discarded by the engine", ruleDef.Name)
		rs.discard(ruleDef.Name, source, "the event type conditions are contradicting")
		return nil
	}

	rule.order = len(rs.rules)
	rs.rules = append(rs.rules, rule)
	rs.byID[ruleDef.ID] = rule

	for eventType := range scope {
		bucket := rs.ruleBuckets[eventType]
		if bucket == nil {
			bucket = &RuleBucket{}
			rs.ruleBuckets[eventType] = bucket
		}
		bucket.AddRule(rule)
	}

	rs.reportMu.Lock()
	rs.report = nil
	rs.reportMu.Unlock()

	return nil
}

func (rs *RuleSet) discard(name, source, reason string) {
	rs.discarded = append(rs.discarded, DiscardedRule{Name: name, Source: source, Reason: reason})
}

// checkEngineVersion verifies the rule can run in this engine version.
func checkEngineVersion(def *policy.RuleDef) error {
	if version.IsDev() || def.MinEngineVersion == "" {
		return nil
	}
	minEngineVer, err := semver.NewSemver(def.MinEngineVersion)
	if err != nil {
		return ErrMalformedMinEngineVer(def.Name, def.MinEngineVersion, err)
	}
	if minEngineVer.GreaterThan(version.Sem()) {
		return ErrIncompatibleRule(def.Name, def.MinEngineVersion)
	}
	return nil
}

// validateEventRefs checks the values of the event name and category fields.
func validateEventRefs(rule *Rule) error {
	// names, categories := rule.evaluator.EventRefs()
	// for _, name := range names {
	// 	if !event.IsTypeKnown(name) {
	// 		return ErrUnknownEventName(rule.Name, name)
	// 	}
	// }
	// for _, cat := range categories {
	// 	if !event.IsCategoryKnown(cat) {
	// 		return ErrUnknownCategoryName(rule.Name, cat)
	// 	}
	// }
	return nil
}

// AddListener adds a listener on the rule set.
func (rs *RuleSet) AddListener(listener RuleSetListener) {
	rs.listenersLock.Lock()
	defer rs.listenersLock.Unlock()
	rs.listeners = append(rs.listeners, listener)\
}

// NotifyRuleMatch notifies the rule set listeners that the rule matched. The
// notification stops at the first listener that returns false.
func (rs *RuleSet) NotifyRuleMatch(rule *Rule, events []*event.Event) {
	rs.listenersLock.RLock()
	defer rs.listenersLock.RUnlock()

	for _, listener := range rs.listeners {
		if !listener.RuleMatch(rule, events) {
			break
		}
	}
}

// Evaluate evaluates the event against the rules in the bucket of the event
// type, and notifies the listeners about every rule that matches. Only the first
// rule that matches is notified if the match all strategy is not enabled. It
// returns true if any rule matched.
func (rs *RuleSet) Evaluate(evt *event.Event) bool {
	if rs == nil || len(rs.rules) == 0 {
		return false
	}

	eventType := evt.Type

	bucket := rs.ruleBuckets[eventType]
	if bucket == nil {
		return false
	}

	valuer := eval.AcquireValuerCache()
	defer valuer.Release()

	var matched bool
	for _, rule := range bucket.rules {
		evts, ok := rule.Evaluate(evt, valuer)
		if !ok {
			continue
		}
		matched = true
		rs.NotifyRuleMatch(rule, evts)
		if !rs.matchAll {
			break
		}
	}

	return matched
}

// ListRuleIDs returns the identifiers of the rules in the order they were loaded.
func (rs *RuleSet) ListRuleIDs() []policy.RuleID {
	if rs == nil {
		return nil
	}
	ids := make([]policy.RuleID, 0, len(rs.rules))
	for _, r := range rs.rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// ListMacroIDs returns the identifiers of the macros.
func (rs *RuleSet) ListMacroIDs() []policy.MacroID {
	if rs == nil {
		return nil
	}
	ids := make([]policy.MacroID, 0, len(rs.macroDefs))
	for _, m := range rs.macroDefs {
		ids = append(ids, m.ID)
	}
	return ids
}

// GetRules returns the active rules in the order they were loaded.
func (rs *RuleSet) GetRules() []*Rule {
	if rs == nil {
		return nil
	}
	return rs.rules
}

// GetRuleByID returns the rule by the given ID.
func (rs *RuleSet) GetRuleByID(id policy.RuleID) *Rule {
	for _, bucket := range rs.ruleBuckets {
		for _, rule := range bucket.rules {
			if rule.ID == id {
				return rule
			}
		}
	}
	return nil
}

// GetRuleMap returns the active rules indexed by their identifiers.
func (rs *RuleSet) GetRuleMap() map[policy.RuleID]*Rule {
	if rs == nil {
		return nil
	}
	m := make(map[policy.RuleID]*Rule, len(rs.byID))
	for id, r := range rs.byID {
		m[id] = r
	}
	return m
}

// GetPolicies returns the policies the rule set was built from.
func (rs *RuleSet) GetPolicies() []*policy.Policy {
	if rs == nil {
		return nil
	}
	return rs.policies
}

// GetMacros returns the macro store.
func (rs *RuleSet) GetMacros() *macro.Store { return rs.macros }

// MatchAll returns true if the match all strategy is enabled.
func (rs *RuleSet) MatchAll() bool { return rs.matchAll }

// // HasSequences determines if there is any sequence rule in the rule set.
// func (rs *RuleSet) HasSequences() bool { return len(rs.sequences) > 0 }

// HasRulesForEventType returns true if there is at least one rule for the event type.
func (rs *RuleSet) HasRulesForEventType(t event.Type) bool {
	return rs.ruleBuckets[t] != nil
}

// GetBucket returns the bucket of the rules for the event type.
func (rs *RuleSet) GetBucket(t event.Type) *RuleBucket {
	return rs.ruleBuckets[t]
}

// ListFields returns the unique fields referenced by all the rules.
func (rs *RuleSet) ListFields() []string {
	if rs == nil {
		return nil
	}
	var (
		flds []string
		seen = make(map[string]struct{})
	)
	for _, r := range rs.rules {
		for _, f := range r.evaluator.GetFields() {
			name := string(f.Name)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			flds = append(flds, name)
		}
	}
	slices.Sort(flds)
	return flds
}

// GetApprovers computes the approvers for the event source with the given
// capabilities.
func (rs *RuleSet) GetApprovers(caps ApproverCaps) *Approvers {
	if rs == nil {
		return computeApprovers(nil, caps)
	}
	return computeApprovers(rs.rules, caps)
}

// Report returns the report about the rule set.
func (rs *RuleSet) Report() *RuleSetReport {
	if rs == nil {
		return &RuleSetReport{}
	}
	rs.reportMu.Lock()
	defer rs.reportMu.Unlock()
	if rs.report == nil {
		rs.report = buildReport(rs.rules)
		rs.report.Approvers = computeApprovers(rs.rules, rs.approverCaps)
		rs.report.Discarded = slices.Clone(rs.discarded)
	}
	return rs.report
}

// Approvers returns the approvers derived from the rules.
func (rs *RuleSet) Approvers() *Approvers { return rs.Report().Approvers }

// Len returns the number of rules.
func (rs *RuleSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// LoadPolicies loads policies from the provided policy loader and returns
func (rs *RuleSet) LoadPolicies() ([]*policy.RuleDef, *multierror.Error) {
	var (
		errs          *multierror.Error
		allRules      []*policy.RuleDef
		filteredRules []*policy.RuleDef
		allMacros     []*policy.MacroDef
		macroIndex    = make(map[string]*policy.MacroDef)
		rulesIndex    = make(map[string]*policy.RuleDef)
	)

	policies, err := rs.policyLoader.LoadPolicies(opts)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	rs.policies.Store(policies)

	for _, policy := range policies {
		if len(policy.Macros) == 0 && len(policy.Rules) == 0 && (policy.Info.Name != DefaultPolicyName && !policy.Info.IsInternal) {
			errs = multierror.Append(errs, &ErrPolicyLoad{
				Name:    policy.Info.Name,
				Type:    policy.Info.Type,
				Version: policy.Info.Version,
				Source:  policy.Info.Source,
				Err:     ErrPolicyIsEmpty,
			})
			continue
		}

		for _, macro := range policy.GetAcceptedMacros() {
			if existingMacro := macroIndex[macro.Def.ID]; existingMacro != nil {
				if err := existingMacro.MergeWith(macro); err != nil {
					errs = multierror.Append(errs, err)
				}
			} else {
				macroIndex[macro.Def.ID] = macro
				allMacros = append(allMacros, macro)
			}
		}

		for _, rule := range policy.GetAcceptedRules() {
			if existingRule := rulesIndex[rule.Def.ID]; existingRule != nil {
				existingRule.UsedBy = append(existingRule.UsedBy, rule.Policy)
				existingRule.MergeWith(rule)
			} else {
				rulesIndex[rule.Def.ID] = rule
				allRules = append(allRules, rule)
			}
		}

		for _, rule := range policy.GetFilteredRules() {
			if existingRule := rulesIndex[rule.Def.ID]; existingRule != nil {
				// if the rule is already in the rules index, this means that a rule with the same ID was already accepted
				// in this case let's only report the version of the rule that was accepted
				continue
			}
			filteredRules = append(filteredRules, rule)
		}
	}

	if err := rs.AddMacros(allMacros); err.ErrorOrNil() != nil {
		errs = multierror.Append(errs, err)
	}

	if err := rs.PopulateFieldsWithRuleActionsData(allRules, opts); err.ErrorOrNil() != nil {
		errs = multierror.Append(errs, err)
	}

	if err := rs.AddRules(allRules); err.ErrorOrNil() != nil {
		errs = multierror.Append(errs, err)
	}

	return filteredRules, errs
}