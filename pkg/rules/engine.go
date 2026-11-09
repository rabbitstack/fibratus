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
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
)

const (
	// heartbeatFastInterval is the heartbeat period after the engine
	// starts or the rules are reloaded
	heartbeatFastInterval = time.Minute
	// heartbeatSlowInterval is the heartbeat period once the fast beats are sent
	heartbeatSlowInterval = 10 * time.Minute
	// heartbeatFastBeats is the number of heartbeats sent at the fast period
	heartbeatFastBeats = 5
)

var (
	ruleMatches   = expvar.NewMap("filter.matches")
	noMatches     = expvar.NewMap("rules.events.nomatch")
	reloads       = expvar.NewInt("rules.reloads")
	reloadFails   = expvar.NewInt("rules.reload.errors")
	heartbeatsOut = expvar.NewInt("rules.heartbeats")

	// ErrRuleAction signals the rule action failed.
	ErrRuleAction = func(rule, action string, err error) error {
		return fmt.Errorf("fail to execute %s action for %q rule: %v", action, rule, err)
	}
)

// Heartbeat describes the state of the rule engine. It is sent periodically
// to tell that the engine is alive and which rules it is running.
type Heartbeat struct {
	// Time is the heartbeat time.
	Time time.Time
	// Hostname is the name of the host the engine runs on.
	Hostname string
	// NumberRules is the number of the rules in the current rule set.
	NumberRules int
	// Policies describes the policies of the current rule set.
	Policies []HeartbeatPolicy
}

// HeartbeatPolicy summarizes the policy in the heartbeat.
type HeartbeatPolicy struct {
	Name    string
	Source  string
	Version string
	// Rules is the number of the active rules coming from the policy.
	Rules int
}

// HeartbeatSender delivers the engine heartbeats.
type HeartbeatSender interface {
	SendHeartbeat(h *Heartbeat) error
}

// logHeartbeatSender is the default heartbeat sender, which only logs the heartbeat.
type logHeartbeatSender struct{}

func (logHeartbeatSender) SendHeartbeat(h *Heartbeat) error {
	log.Debugf("rule engine heartbeat: rules=%d policies=%d", h.NumberRules, len(h.Policies))
	return nil
}

// RulesetLoadedFunc is invoked each time the engine tries to load the rule set. If
// loading failed, the rule set is nil and the error describes why the engine keeps
// running with the previous rule set.
type RulesetLoadedFunc func(rs *RuleSet, err error)

// ReloadFunc is invoked after the engine has replaced the rule set.
type ReloadFunc func(report *RuleSetReport)

// EngineOption customizes the engine.
type EngineOption func(*Engine)

// WithProviders sets the providers that supply the policies. By default,
// the policies are loaded from the rule and macro paths from the configuration.
func WithProviders(providers ...policy.Provider) EngineOption {
	return func(e *Engine) { e.providers = providers }
}

// WithActions sets the implementations of the rule actions.
func WithActions(actions Actions) EngineOption {
	return func(e *Engine) { e.actions = actions }
}

// WithRuleSetOptions sets the options for the rule sets the engine builds.
func WithRuleSetOptions(opts ...Option) EngineOption {
	return func(e *Engine) { e.rsOpts = opts }
}

// WithHeartbeatSender sets the heartbeat sender.
func WithHeartbeatSender(sender HeartbeatSender) EngineOption {
	return func(e *Engine) { e.heartbeat = sender }
}

// WithHeartbeatIntervals sets the heartbeat periods. The fast period is used
// for the first beats after the engine starts or the rules are reloaded.
func WithHeartbeatIntervals(fast, slow time.Duration) EngineOption {
	return func(e *Engine) { e.heartbeatFast, e.heartbeatSlow = fast, slow }
}

// Engine is the rule engine. It owns the lifecycle of the rule set, which is
// built from the policies the providers supply, and replaces it as a whole each
// time the policies change. A rule set that fails to build never replaces the
// working one, so the engine keeps evaluating the events with the rules it has.
//
// The engine listens to the matches of the rule sets it builds. On a match, it
// tags the events of the match, sends the alert via the alert senders and runs
// the actions that the rule declares. While it runs, the engine reloads the
// policies in a goroutine when the providers report the changes, or when it is
// asked to, and periodically sends the heartbeats.
type Engine struct {
	// RWMutex guards the callbacks
	sync.RWMutex
	// reloadMu serializes the rule set replacements
	reloadMu sync.Mutex

	cfg          config.RulesConfig
	providers    []policy.Provider
	policyLoader *policy.Loader
	rsOpts       []Option
	actions      Actions

	ruleSet atomic.Pointer[RuleSet]

	rulesLoaded RulesetLoadedFunc
	reloadFns   []ReloadFunc
	matchFns    []func(rule *Rule, events []*event.Event)

	heartbeat      HeartbeatSender
	heartbeatFast  time.Duration
	heartbeatSlow  time.Duration
	heartbeatReset chan struct{}
	hostname       string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewEngine creates the rule engine. Call Start to load the rules and begin
// watching the policy providers.
func NewEngine(cfg config.RulesConfig, opts ...EngineOption) *Engine {
	e := &Engine{
		cfg:            cfg,
		heartbeat:      logHeartbeatSender{},
		heartbeatFast:  heartbeatFastInterval,
		heartbeatSlow:  heartbeatSlowInterval,
		heartbeatReset: make(chan struct{}, 1),
	}
	e.hostname, _ = os.Hostname()
	for _, opt := range opts {
		opt(e)
	}
	if len(e.providers) == 0 {
		e.providers = []policy.Provider{policy.NewDirProvider(cfg.RulePaths, cfg.MacroPaths)}
	}
	e.policyLoader = policy.NewLoader(policy.DefaultLoadOptions(), e.providers...)
	e.ruleSet.Store(NewEmptyRuleSet())
	return e
}

// Start loads the rules, starts the policy providers, and spins up the goroutines
// that reload the policies and send the heartbeats. The policies are reloaded when
// a provider reports a change, or when a signal arrives on the reload channel, which
// may be nil. The engine stops when the context is cancelled or Stop is called.
// If the initial load fails, the engine doesn't start.
func (e *Engine) Start(ctx context.Context, reloadChan <-chan struct{}) error {
	if err := e.LoadPolicies(true); err != nil {
		return err
	}
	if err := e.policyLoader.Watch(); err != nil {
		return err
	}

	ctx, e.cancel = context.WithCancel(ctx)

	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		e.reloadLoop(ctx, reloadChan)
	}()
	go func() {
		defer e.wg.Done()
		e.heartbeatLoop(ctx)
	}()

	return nil
}

// Stop stops the goroutines and closes the policy providers.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	if err := e.policyLoader.Close(); err != nil {
		log.Errorf("unable to close policy providers: %v", err)
	}
	e.wg.Wait()
}

// reloadLoop reloads the policies when the providers report new policies
// or when the reload signal arrives. A panic while reloading is logged,
// and doesn't stop the loop.
func (e *Engine) reloadLoop(ctx context.Context, reloadChan <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-reloadChan:
			log.Info("reload signal received, reloading policies")
			e.safely("reload policies", func() { _ = e.ReloadPolicies() })
		case <-e.policyLoader.NewPolicyReady():
			log.Info("new policies are ready, reloading")
			e.safely("reload policies", func() { _ = e.ReloadPolicies() })
		}
	}
}

func (e *Engine) safely(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic while trying to %s: %v\n%s", what, r, debug.Stack())
		}
	}()
	fn()
}

// ReloadPolicies reloads the policies from the providers and replaces the
// rule set. The engine keeps the current rule set if reloading fails.
func (e *Engine) ReloadPolicies() error {
	log.Info("reloading policies")
	return e.LoadPolicies(true)
}

// LoadPolicies loads the policies from all providers, builds the rule set and
// replaces the current one. The current rule set stays in place if the policies
// can't be loaded or any rule fails to compile. If sendLoadedReport is set, the
// heartbeat is sent right away, and the heartbeat period restarts.
func (e *Engine) LoadPolicies(sendLoadedReport bool) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	policies, err := e.policyLoader.LoadPolicies()
	if err != nil {
		return e.loadFailed(err)
	}

	opts := append([]Option{WithMatchAll(e.cfg.MatchAll)}, e.rsOpts...)
	rs, err := NewRuleSet(policies, opts...)
	if err != nil {
		return e.loadFailed(err)
	}

	// the engine is notified about every rule that matches
	rs.AddListener(e)

	prev := e.ruleSet.Swap(rs)
	reloads.Add(1)

	report := rs.Report()
	log.Infof("rule set loaded: %s", report)

	// the event source enables the providers and event types at startup,
	// so the rules that need events it didn't enable can't match them
	if prev != nil && prev.Len() > 0 {
		if missing := prev.Report().Missing(report); len(missing) > 0 {
			log.Warnf("the reloaded rules use the event types the event "+
				"source wasn't started with: %v. Restart Fibratus to capture them", missing)
		}
	}

	e.RLock()
	loaded, fns := e.rulesLoaded, append([]ReloadFunc(nil), e.reloadFns...)
	e.RUnlock()
	if loaded != nil {
		loaded(rs, nil)
	}
	for _, fn := range fns {
		fn(report)
	}

	if sendLoadedReport {
		select {
		case e.heartbeatReset <- struct{}{}:
		default:
		}
	}

	return nil
}

func (e *Engine) loadFailed(err error) error {
	reloadFails.Add(1)
	log.Errorf("unable to load policies. The rule set remains unchanged: %v", err)
	e.RLock()
	loaded := e.rulesLoaded
	e.RUnlock()
	if loaded != nil {
		loaded(nil, err)
	}
	return err
}

// heartbeatLoop sends the heartbeats. The first beats are sent at the fast
// period, and the following at the slow one. The reload of the rule set sends the
// heartbeat immediately, and restarts the fast period.
func (e *Engine) heartbeatLoop(ctx context.Context) {
	beats := heartbeatFastBeats
	ticker := time.NewTicker(e.heartbeatFast)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.heartbeatReset:
			beats = heartbeatFastBeats
			ticker.Reset(e.heartbeatFast)
			e.safely("send heartbeat", e.sendHeartbeat)
		case <-ticker.C:
			e.safely("send heartbeat", e.sendHeartbeat)
			if beats > 0 {
				beats--
				if beats == 0 {
					ticker.Reset(e.heartbeatSlow)
				}
			}
		}
	}
}

// sendHeartbeat sends the heartbeat about the current rule set.
func (e *Engine) sendHeartbeat() {
	rs := e.ruleSet.Load()

	hb := &Heartbeat{Time: time.Now(), Hostname: e.hostname, NumberRules: rs.Len()}
	for _, p := range rs.GetPolicies() {
		hp := HeartbeatPolicy{Name: p.Name, Source: p.Source, Version: p.Version}
		for _, r := range rs.GetRules() {
			if r.Source == p.Source {
				hp.Rules++
			}
		}
		hb.Policies = append(hb.Policies, hp)
	}

	if err := e.heartbeat.SendHeartbeat(hb); err != nil {
		log.Errorf("unable to send heartbeat: %v", err)
		return
	}
	heartbeatsOut.Add(1)
}

// SetRulesetLoadedCallback sets the function called each time the engine
// tries to load the rule set.
func (e *Engine) SetRulesetLoadedCallback(cb RulesetLoadedFunc) {
	e.Lock()
	defer e.Unlock()
	e.rulesLoaded = cb
}

// OnReload registers the function called after the rule set is replaced.
func (e *Engine) OnReload(fn ReloadFunc) {
	e.Lock()
	defer e.Unlock()
	e.reloadFns = append(e.reloadFns, fn)
}

// RegisterMatchFunc registers the function called for every rule match.
func (e *Engine) RegisterMatchFunc(fn func(rule *Rule, events []*event.Event)) {
	e.Lock()
	defer e.Unlock()
	e.matchFns = append(e.matchFns, fn)
}

// GetRuleSet returns the current rule set.
func (e *Engine) GetRuleSet() *RuleSet { return e.ruleSet.Load() }

// Report returns the report of the current rule set.
func (e *Engine) Report() *RuleSetReport { return e.ruleSet.Load().Report() }

// Approvers returns the approvers of the current rule set. Since the rule
// set is replaced when the rules change, consumers should call this method
// every time they need the approvers, and never hold on to the result.
func (e *Engine) Approvers() *Approvers { return e.ruleSet.Load().Approvers() }

// Len returns the number of rules in the current rule set.
func (e *Engine) Len() int { return e.ruleSet.Load().Len() }

// HandleEvent evaluates the event against the current rule set. The events
// that trigger the rules are tagged with the rule name and the rule labels in the
// event metadata, so the downstream consumers can tell which events matched.
// The failures of rule actions are logged, and don't prevent the remaining
// actions from running, nor do they stop the event from being processed.
func (e *Engine) HandleEvent(evt *event.Event) error {
	rs := e.ruleSet.Load()
	if rs.Len() == 0 {
		return nil
	}

	if !rs.Evaluate(evt) && rs.HasRulesForEventType(evt.Type) {
		noMatches.Add(evt.Type.String(), 1)
	}

	return nil
}

// RuleMatch implements the RuleSetListener interface. It tags the events of
// the match, sends the alert through the alert senders, and runs the actions
// that the rule declares. It always returns true, so the other listeners are
// notified as well.
func (e *Engine) RuleMatch(rule *Rule, events []*event.Event) bool {
	m := RuleMatch{Rule: rule, Events: events}
	name := rule.Name
	ruleMatches.Add(name, 1)
	log.Debugf("[%s] rule matched", name)

	for _, evt := range events {
		evt.AddMeta(event.RuleNameKey, name)
		for k, v := range rule.Labels {
			evt.AddMeta(event.MetadataKey(k), v)
		}
	}

	e.RLock()
	fns := e.matchFns
	e.RUnlock()
	for _, fn := range fns {
		fn(rule, events)
	}

	if err := e.runActions(m); err != nil {
		log.Errorf("unable to execute rule actions: %v", err)
	}

	return true
}

// runActions executes the rule actions. Sending the alert is the implicit
// action carried out each time there is a match. The other actions run only
// if they are declared in the rule definition.
func (e *Engine) runActions(m RuleMatch) error {
	var errs []error
	name := m.Rule.Name

	if e.actions.Alerter != nil {
		if err := e.actions.Alerter.Alert(m); err != nil {
			errs = append(errs, ErrRuleAction(name, "alert", err))
		}
	}

	for _, act := range m.Rule.Action {
		switch {
		case act.Kill != nil:
			if e.actions.ProcessKiller == nil {
				log.Warnf("[%s] the kill action is not available", name)
				continue
			}
			log.Infof("executing kill action: rule=%s", name)
			if err := e.actions.ProcessKiller.Kill(m); err != nil {
				errs = append(errs, ErrRuleAction(name, "kill", err))
			}
		case act.Isolate != nil:
			if e.actions.Isolator == nil {
				log.Warnf("[%s] the isolate action is not available", name)
				continue
			}
			log.Infof("executing isolate action: rule=%s", name)
			if err := e.actions.Isolator.Isolate(act.Isolate.Whitelist); err != nil {
				errs = append(errs, ErrRuleAction(name, "isolate", err))
			}
		}
	}

	return multierror.Wrap(errs...)
}

var _ RuleSetListener = (*Engine)(nil)
