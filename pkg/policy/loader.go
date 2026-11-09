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
package policy

import (
	"fmt"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
)

// LoadOptions controls how the loader post-processes provider policies.
type LoadOptions struct {
	RuleFilters  []RuleFilter
	MacroFilters []MacroFilter
}

// DefaultLoadOptions returns the options that drop disabled rules.
func DefaultLoadOptions() LoadOptions {
	return LoadOptions{RuleFilters: []RuleFilter{EnabledRuleFilter}}
}

// ReloadHandler is invoked with the freshly loaded policies when the
// providers report that the policies have changed. If the handler returns
// an error, the loader logs it and keeps waiting for the next change.
type ReloadHandler func(policies []*Policy) error

// PolicyReloadNotification contains information about a policy reload event
type PolicyReloadNotification struct {
	Silent bool // If true, skip reporting heartbeat events
}

// Loader aggregates policies from all registered providers, validates
// them as a whole and drives the reloads when providers report changes.
type Loader struct {
	providers []Provider
	opts      LoadOptions

	// reloadLock serializes reloads triggered by providers
	reloadLock sync.Mutex
	listeners  []chan PolicyReloadNotification
	handler    ReloadHandler
	closed     bool

	// ready signals that the providers have new policies. The channel has
	// room for a single signal, so the bursts of changes are coalesced.
	ready chan struct{}
}

// NewLoader creates the policy loader.
func NewLoader(opts LoadOptions, providers ...Provider) *Loader {
	l := &Loader{providers: providers, opts: opts, ready: make(chan struct{}, 1)}

	return l
}

// LoadPolicies reads the policies from every provider, applies the load filters and
// verifies that rule and macro identifiers are unique across all policies.
// The returned policies contain everything that could be loaded, and the
// error aggregates all failures. Callers that require a consistent state,
// like the rule engine on reload, must treat any error as a failed load.
func (l *Loader) LoadPolicies() ([]*Policy, error) {
	var (
		policies []*Policy
		errs     []error
	)

	ruleSrc := make(map[RuleID]string)
	macroSrc := make(map[MacroID]string)

	for _, provider := range l.providers {
		policies, err := provider.LoadPolicies()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s provider: %w", provider.Type(), err))
		}
		for _, policy := range policies {
			policy = l.filter(policy)

			for _, m := range policy.Macros {
				if src, ok := macroSrc[m.ID]; ok {
					errs = append(errs, fmt.Errorf("macro %q in %s is already defined in %s", m.ID, policy.Source, src))
					continue
				}
				macroSrc[m.ID] = policy.Source
			}
			for _, r := range policy.Rules {
				if src, ok := ruleSrc[r.ID]; ok {
					errs = append(errs, fmt.Errorf("rule %q uses duplicate id %s (already defined in %s, found in %s)",
						r.Name, r.ID, src, policy.Source))
					continue
				}
				ruleSrc[r.ID] = policy.Source
			}
			policies = append(policies, policy)
		}
	}

	return policies, multierror.Wrap(errs...)
}

// filter returns a copy of the policy with rejected rules/macros removed.
func (l *Loader) filter(p *Policy) *Policy {
	cp := *p
	cp.Macros = make([]*MacroDef, 0, len(p.Macros))
	cp.Rules = make([]*RuleDef, 0, len(p.Rules))

	for _, m := range p.Macros {
		if acceptMacro(m, l.opts.MacroFilters) {
			cp.Macros = append(cp.Macros, m)
		}
	}
	for _, r := range p.Rules {
		if acceptRule(r, l.opts.RuleFilters) {
			cp.Rules = append(cp.Rules, r)
		}
	}
	return &cp
}

func acceptRule(r *RuleDef, filters []RuleFilter) bool {
	for _, f := range filters {
		if !f(r) {
			return false
		}
	}
	return true
}

func acceptMacro(m *MacroDef, filters []MacroFilter) bool {
	for _, f := range filters {
		if !f(m) {
			return false
		}
	}
	return true
}

// Start registers the reload handler and starts all providers. Every time
// any provider reports a change, all policies are reloaded. If the reload
// fails, the handler is not called, so the consumer keeps working with the
// policies it already has.
func (l *Loader) Start(handler ReloadHandler) error {
	l.reloadLock.Lock()
	l.handler = handler
	l.reloadLock.Unlock()

	return l.startProviders(l.reload)
}

// Watch starts all providers. When any provider reports a change, the
// loader signals it on the channel returned by NewPolicyReady, and it is up to
// the consumer to call Load. It is an alternative to Start for the consumers
// that drive the reloads from their own goroutines.
func (l *Loader) Watch() error {
	return l.startProviders(l.notify)
}

// NewPolicyReady returns the channel that receives a signal each time
// the providers report new policies. Signals are coalesced: if the consumer
// is busy, the pending signal is kept until it reads it.
func (l *Loader) NewPolicyReady() <-chan struct{} { return l.ready }

func (l *Loader) notify() {
	l.reloadLock.Lock()
	closed := l.closed
	l.reloadLock.Unlock()
	if closed {
		return
	}
	select {
	case l.ready <- struct{}{}:
	default:
	}
}

func (l *Loader) startProviders(onChange func()) error {
	l.reloadLock.Lock()
	l.closed = false
	l.reloadLock.Unlock()

	for i, p := range l.providers {
		p.SetOnPoliciesChanged(onChange)
		if err := p.Start(); err != nil {
			// roll back the providers that were already started
			for _, started := range l.providers[:i] {
				_ = started.Close()
			}
			return fmt.Errorf("unable to start %s provider: %w", p.Type(), err)
		}
	}
	return nil
}

func (l *Loader) reload() {
	l.reloadLock.Lock()
	defer l.reloadLock.Unlock()

	if l.handler == nil {
		return
	}

	log.Info("policy change detected, reloading rules")

	policies, err := l.LoadPolicies()
	if err != nil {
		log.Errorf("unable to reload policies. The rule set remains unchanged: %v", err)
		return
	}
	if err := l.handler(policies); err != nil {
		log.Errorf("unable to apply reloaded policies. The rule set remains unchanged: %v", err)
	}
}

// Close closes all providers.
func (l *Loader) Close() error {
	l.reloadLock.Lock()
	l.handler = nil
	l.closed = true
	l.reloadLock.Unlock()

	var errs []error
	for _, p := range l.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return multierror.Wrap(errs...)
}
