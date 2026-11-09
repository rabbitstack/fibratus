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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a test provider whose policies can be changed at runtime.
type fakeProvider struct {
	typ      string
	mu       sync.Mutex
	policies []*Policy
	err      error
	cb       func()
	started  bool
	closed   bool
	startErr error
}

func (p *fakeProvider) Type() string {
	if p.typ == "" {
		return "fake"
	}
	return p.typ
}

func (p *fakeProvider) Load() ([]*Policy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.policies, p.err
}

func (p *fakeProvider) SetOnPoliciesChanged(cb func()) { p.cb = cb }
func (p *fakeProvider) Start() error                   { p.started = true; return p.startErr }
func (p *fakeProvider) Close() error                   { p.closed = true; return nil }

func (p *fakeProvider) set(policies []*Policy, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policies, p.err = policies, err
}

func rulePolicy(source string, rules ...*RuleDef) *Policy {
	return &Policy{ID: PolicyID(source), Source: source, Type: BehaviourPolicyType, Rules: rules}
}

func rule(id, name string) *RuleDef {
	return &RuleDef{ID: RuleID(id), Name: name, Condition: "evt.name = 'x'"}
}

func TestLoaderMergesProviders(t *testing.T) {
	p1 := &fakeProvider{policies: []*Policy{
		{ID: "p1", Source: "p1", Macros: []*MacroDef{{ID: "m1", Expression: "x"}}},
		rulePolicy("p1-rules", rule(id1, "r1")),
	}}
	p2 := &fakeProvider{typ: "other", policies: []*Policy{rulePolicy("p2", rule(id2, "r2"))}}

	l := NewLoader(DefaultLoadOptions(), p1, p2)
	policies, err := l.Load()
	require.NoError(t, err)
	require.Len(t, policies, 3)
	assert.Equal(t, PolicyID("p1"), policies[0].ID)
	assert.Equal(t, RuleID(id2), policies[2].Rules[0].ID)
}

func TestLoaderFilters(t *testing.T) {
	disabled := false
	off := rule(id2, "disabled")
	off.Enabled = &disabled

	macro := &MacroDef{ID: "internal_macro", Expression: "x"}
	keep := &MacroDef{ID: "keep_macro", Expression: "x"}

	p := &fakeProvider{policies: []*Policy{
		{Source: "p", Macros: []*MacroDef{macro, keep}, Rules: []*RuleDef{rule(id1, "enabled"), off}},
	}}

	opts := DefaultLoadOptions()
	opts.MacroFilters = []MacroFilter{func(m *MacroDef) bool { return m.ID != "internal_macro" }}

	policies, err := NewLoader(opts, p).Load()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Rules, 1)
	assert.Equal(t, "enabled", policies[0].Rules[0].Name)
	require.Len(t, policies[0].Macros, 1)
	assert.Equal(t, "keep_macro", policies[0].Macros[0].ID)

	// the provider-owned policy is not mutated
	assert.Len(t, p.policies[0].Rules, 2)
	assert.Len(t, p.policies[0].Macros, 2)

	// no filters keep the disabled rule
	policies, err = NewLoader(LoadOptions{}, p).Load()
	require.NoError(t, err)
	assert.Len(t, policies[0].Rules, 2)
}

func TestLoaderDisabledRuleDoesNotCollide(t *testing.T) {
	disabled := false
	off := rule(id1, "disabled copy")
	off.Enabled = &disabled
	p := &fakeProvider{policies: []*Policy{
		rulePolicy("a", off),
		rulePolicy("b", rule(id1, "enabled copy")),
	}}
	_, err := NewLoader(DefaultLoadOptions(), p).Load()
	require.NoError(t, err)
}

func TestLoaderDuplicateIDs(t *testing.T) {
	p := &fakeProvider{policies: []*Policy{
		{Source: "a.yml", Macros: []*MacroDef{{ID: "m", Expression: "x"}}, Rules: []*RuleDef{rule(id1, "first")}},
		{Source: "b.yml", Macros: []*MacroDef{{ID: "m", Expression: "y"}}, Rules: []*RuleDef{rule(id1, "second")}},
	}}
	_, err := NewLoader(DefaultLoadOptions(), p).Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `rule "second" uses duplicate id `+id1)
	assert.Contains(t, err.Error(), "a.yml")
	assert.Contains(t, err.Error(), "b.yml")
	assert.Contains(t, err.Error(), `macro "m" in b.yml is already defined in a.yml`)
}

func TestLoaderDuplicateAcrossProviders(t *testing.T) {
	p1 := &fakeProvider{policies: []*Policy{rulePolicy("one", rule(id1, "a"))}}
	p2 := &fakeProvider{typ: "grpc", policies: []*Policy{rulePolicy("two", rule(id1, "b"))}}
	_, err := NewLoader(DefaultLoadOptions(), p1, p2).Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate id")
}

func TestLoaderProviderError(t *testing.T) {
	p1 := &fakeProvider{typ: "dir", policies: []*Policy{rulePolicy("ok", rule(id1, "ok"))}, err: errors.New("bad.yml is broken")}
	p2 := &fakeProvider{typ: "grpc", err: errors.New("connection refused")}

	policies, err := NewLoader(DefaultLoadOptions(), p1, p2).Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dir provider")
	assert.Contains(t, err.Error(), "bad.yml is broken")
	assert.Contains(t, err.Error(), "grpc provider")
	assert.Contains(t, err.Error(), "connection refused")
	// partial results are returned
	assert.Len(t, policies, 1)
}

func TestLoaderReload(t *testing.T) {
	p := &fakeProvider{policies: []*Policy{rulePolicy("a", rule(id1, "a"))}}
	l := NewLoader(DefaultLoadOptions(), p)

	got := make(chan []*Policy, 4)
	require.NoError(t, l.Start(func(policies []*Policy) error {
		got <- policies
		return nil
	}))
	assert.True(t, p.started)
	require.NotNil(t, p.cb)

	// new rule shows up
	p.set([]*Policy{rulePolicy("a", rule(id1, "a")), rulePolicy("b", rule(id2, "b"))}, nil)
	p.cb()
	select {
	case policies := <-got:
		assert.Len(t, policies, 2)
	case <-time.After(time.Second):
		t.Fatal("reload handler was not called")
	}
}

func TestLoaderReloadErrorKeepsCurrentState(t *testing.T) {
	p := &fakeProvider{policies: []*Policy{rulePolicy("a", rule(id1, "a"))}}
	l := NewLoader(DefaultLoadOptions(), p)

	var calls int
	require.NoError(t, l.Start(func([]*Policy) error { calls++; return nil }))

	// provider error: handler is not called
	p.set([]*Policy{rulePolicy("a", rule(id1, "a"))}, errors.New("broken rule"))
	p.cb()
	assert.Equal(t, 0, calls)

	// duplicate ids: handler is not called
	p.set([]*Policy{rulePolicy("a", rule(id1, "a")), rulePolicy("b", rule(id1, "b"))}, nil)
	p.cb()
	assert.Equal(t, 0, calls)

	// recovers once policies are valid again
	p.set([]*Policy{rulePolicy("a", rule(id1, "a"))}, nil)
	p.cb()
	assert.Equal(t, 1, calls)
}

func TestLoaderReloadHandlerError(t *testing.T) {
	p := &fakeProvider{policies: []*Policy{rulePolicy("a", rule(id1, "a"))}}
	l := NewLoader(DefaultLoadOptions(), p)

	var calls int
	require.NoError(t, l.Start(func([]*Policy) error { calls++; return errors.New("compile error") }))
	p.cb()
	p.cb() // loader keeps working after a handler failure
	assert.Equal(t, 2, calls)
}

func TestLoaderStartError(t *testing.T) {
	ok := &fakeProvider{}
	bad := &fakeProvider{typ: "grpc", startErr: errors.New("boom")}
	l := NewLoader(DefaultLoadOptions(), ok, bad)

	err := l.Start(func([]*Policy) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to start grpc provider")
	// providers started before the failing one are rolled back
	assert.True(t, ok.closed)
}

func TestLoaderClose(t *testing.T) {
	p1, p2 := &fakeProvider{}, &fakeProvider{}
	l := NewLoader(DefaultLoadOptions(), p1, p2)

	var calls int
	require.NoError(t, l.Start(func([]*Policy) error { calls++; return nil }))
	require.NoError(t, l.Close())
	assert.True(t, p1.closed)
	assert.True(t, p2.closed)

	// reload callbacks arriving after close are ignored
	p1.cb()
	assert.Equal(t, 0, calls)
}

func TestLoaderWatchSignalsNewPolicies(t *testing.T) {
	p := &fakeProvider{}
	l := NewLoader(DefaultLoadOptions(), p)
	require.NoError(t, l.Watch())
	assert.True(t, p.started)

	select {
	case <-l.NewPolicyReady():
		t.Fatal("unexpected signal")
	default:
	}

	p.cb()
	select {
	case <-l.NewPolicyReady():
	default:
		t.Fatal("expected the signal")
	}

	// the bursts of changes are coalesced into a single signal
	p.cb()
	p.cb()
	p.cb()
	<-l.NewPolicyReady()
	select {
	case <-l.NewPolicyReady():
		t.Fatal("signals should be coalesced")
	default:
	}
}

func TestLoaderWatchDoesNotLoadOnItsOwn(t *testing.T) {
	p := &fakeProvider{policies: []*Policy{rulePolicy("a.yml", rule("1", "r1"))}}
	l := NewLoader(DefaultLoadOptions(), p)
	require.NoError(t, l.Watch())
	p.cb()
	// the consumer decides when to load
	policies, err := l.Load()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestLoaderWatchStartErrorAndClose(t *testing.T) {
	good, bad := &fakeProvider{}, &fakeProvider{startErr: errors.New("boom")}
	l := NewLoader(DefaultLoadOptions(), good, bad)
	require.Error(t, l.Watch())
	assert.True(t, good.closed, "the started providers are rolled back")

	p := &fakeProvider{}
	l = NewLoader(DefaultLoadOptions(), p)
	require.NoError(t, l.Watch())
	require.NoError(t, l.Close())
	// changes reported after close are ignored
	p.cb()
	select {
	case <-l.NewPolicyReady():
		t.Fatal("no signal expected after close")
	default:
	}
}
