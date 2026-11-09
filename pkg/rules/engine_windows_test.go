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
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider serves the policies that tests can replace at any time.
type fakeProvider struct {
	mu       sync.Mutex
	policies []*policy.Policy
	err      error
	cb       func()
	started  bool
	closed   bool
	startErr error
}

func (p *fakeProvider) Type() string { return "fake" }
func (p *fakeProvider) LoadPolicies() ([]*policy.Policy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.policies, p.err
}
func (p *fakeProvider) SetOnPoliciesChanged(cb func()) { p.cb = cb }
func (p *fakeProvider) Start() error                   { p.started = true; return p.startErr }
func (p *fakeProvider) Close() error                   { p.closed = true; return nil }

// update replaces the policies and notifies the loader like a real provider.
func (p *fakeProvider) update(err error, policies ...*policy.Policy) {
	p.mu.Lock()
	p.policies, p.err = policies, err
	p.mu.Unlock()
	p.cb()
}

type fakeActions struct {
	mu        sync.Mutex
	alerts    []RuleMatch
	kills     []RuleMatch
	isolates  [][]net.IP
	alertErr  error
	killErr   error
	isolateEr error
}

func (a *fakeActions) Alert(m RuleMatch) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, m)
	return a.alertErr
}

func (a *fakeActions) Kill(m RuleMatch) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kills = append(a.kills, m)
	return a.killErr
}

func (a *fakeActions) Isolate(whitelist []net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.isolates = append(a.isolates, whitelist)
	return a.isolateEr
}

func (a *fakeActions) actions() Actions {
	return Actions{Alerter: a, ProcessKiller: a, Isolator: a}
}

type fakeHeartbeats struct {
	mu    sync.Mutex
	beats []*Heartbeat
}

func (f *fakeHeartbeats) SendHeartbeat(h *Heartbeat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats = append(f.beats, h)
	return nil
}

func (f *fakeHeartbeats) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.beats)
}

func (f *fakeHeartbeats) last() *Heartbeat {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.beats) == 0 {
		return nil
	}
	return f.beats[len(f.beats)-1]
}

func newTestEngine(t *testing.T, matchAll bool, p *fakeProvider, actions Actions, opts ...EngineOption) *Engine {
	t.Helper()
	opts = append([]EngineOption{WithProviders(p), WithActions(actions)}, opts...)
	e := NewEngine(config.RulesConfig{Enabled: true, MatchAll: matchAll}, opts...)
	t.Cleanup(e.Stop)
	return e
}

// startEngine starts the engine and returns the channel that triggers the reload.
func startEngine(t *testing.T, e *Engine) chan struct{} {
	t.Helper()
	reload := make(chan struct{})
	require.NoError(t, e.Start(context.Background(), reload))
	return reload
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 3*time.Second, 5*time.Millisecond)
}

func TestEngineStartAndHandleEvent(t *testing.T) {
	kill := def("kill", "evt.name = 'CreateProcess' and ps.name = 'evil.exe'")
	kill.Labels = map[string]string{"tactic.id": "TA0002"}
	kill.Action = []policy.ActionDefinition{{Kill: &policy.KillAction{}}}
	iso := def("isolate", "evt.name = 'CreateFile'")
	whitelist := []net.IP{net.ParseIP("10.0.0.1")}
	iso.Action = []policy.ActionDefinition{{Isolate: &policy.IsolateAction{Whitelist: whitelist}}}

	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", kill, iso, def("plain", "evt.name = 'WriteFile'"))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())
	startEngine(t, e)

	assert.True(t, p.started)
	assert.Equal(t, 3, e.Report().NumberRules)
	assert.Equal(t, 3, e.Len())

	var matched []string
	e.RegisterMatchFunc(func(r *Rule, _ []*event.Event) { matched = append(matched, r.Name) })

	// event that no rule is interested in
	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.RegSetValue)))
	assert.Empty(t, fa.alerts)

	// rule with the kill action
	evil := testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(7, "evil.exe")))
	require.NoError(t, e.HandleEvent(evil))
	require.Len(t, fa.alerts, 1)
	require.Len(t, fa.kills, 1)
	assert.Empty(t, fa.isolates)
	assert.Equal(t, "kill", fa.kills[0].Rule.Name)
	assert.Equal(t, []string{"kill"}, matched)
	// the matched event carries the rule name and labels
	assert.Equal(t, "kill", evil.GetMetaAsString(event.RuleNameKey))
	assert.Equal(t, "TA0002", evil.GetMetaAsString("tactic.id"))

	// the rule with the isolate action
	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.CreateFile)))
	require.Len(t, fa.isolates, 1)
	assert.Equal(t, whitelist, fa.isolates[0])
	assert.Len(t, fa.kills, 1)

	// rule without explicit actions only sends the alert
	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.WriteFile)))
	assert.Len(t, fa.alerts, 3)
	assert.Len(t, fa.kills, 1)
	assert.Len(t, fa.isolates, 1)

	// the event that doesn't satisfy the rule condition isn't marked
	benign := testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(8, "good.exe")))
	require.NoError(t, e.HandleEvent(benign))
	assert.Empty(t, benign.GetMetaAsString(event.RuleNameKey))
}

func TestEngineRuleMatchIsRuleSetListener(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())
	startEngine(t, e)

	rule := e.GetRuleSet().GetRuleByID("id-a")
	evt := testutil.MakeEvent(event.CreateFile)
	// the engine always lets the other listeners be notified
	assert.True(t, e.RuleMatch(rule, []*event.Event{evt}))
	assert.Len(t, fa.alerts, 1)
	assert.Equal(t, "a", evt.GetMetaAsString(event.RuleNameKey))
}

func TestEngineMatchAll(t *testing.T) {
	policies := []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'CreateFile'"))}

	for _, matchAll := range []bool{true, false} {
		p := &fakeProvider{policies: policies}
		fa := &fakeActions{}
		e := newTestEngine(t, matchAll, p, fa.actions())
		startEngine(t, e)
		require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.CreateFile)))
		if matchAll {
			assert.Len(t, fa.alerts, 2)
		} else {
			assert.Len(t, fa.alerts, 1)
		}
	}
}

func TestEngineActionFailuresDontStopOtherActions(t *testing.T) {
	r := def("r", "evt.name = 'CreateFile'")
	r.Action = []policy.ActionDefinition{{Kill: &policy.KillAction{}}, {Isolate: &policy.IsolateAction{}}}
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", r)}}
	fa := &fakeActions{
		alertErr:  errors.New("no senders"),
		killErr:   errors.New("access denied"),
		isolateEr: errors.New("wfp"),
	}
	e := newTestEngine(t, true, p, fa.actions())
	startEngine(t, e)

	evt := testutil.MakeEvent(event.CreateFile)
	require.NoError(t, e.HandleEvent(evt))
	assert.Len(t, fa.alerts, 1)
	assert.Len(t, fa.kills, 1)
	assert.Len(t, fa.isolates, 1)

	// the failures are reported by the action runner
	err := e.runActions(RuleMatch{Rule: e.GetRuleSet().GetRules()[0], Events: []*event.Event{evt}})
	require.Error(t, err)
	for _, s := range []string{"no senders", "access denied", "wfp"} {
		assert.Contains(t, err.Error(), s)
	}
	// the event is still marked
	assert.Equal(t, "r", evt.GetMetaAsString(event.RuleNameKey))
}

func TestEngineWithoutActionImplementations(t *testing.T) {
	r := def("r", "evt.name = 'CreateFile'")
	r.Action = []policy.ActionDefinition{{Kill: &policy.KillAction{}}, {Isolate: &policy.IsolateAction{}}}
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", r)}}
	e := newTestEngine(t, true, p, Actions{})
	startEngine(t, e)

	evt := testutil.MakeEvent(event.CreateFile)
	assert.NotPanics(t, func() { _ = e.HandleEvent(evt) })
	assert.Equal(t, "r", evt.GetMetaAsString(event.RuleNameKey))
}

func TestEngineNotStarted(t *testing.T) {
	e := NewEngine(config.RulesConfig{}, WithProviders(&fakeProvider{}))
	// the engine that wasn't started is a no-op
	assert.NoError(t, e.HandleEvent(testutil.MakeEvent(event.CreateFile)))
	assert.Equal(t, 0, e.Len())
	assert.Equal(t, 0, e.Report().NumberRules)
	assert.True(t, e.Approvers().Approve(event.RegOpenKey, nil))
	// stopping the engine that wasn't started is safe
	assert.NotPanics(t, e.Stop)
}

func TestEngineStartErrors(t *testing.T) {
	// provider failure
	p := &fakeProvider{err: errors.New("boom")}
	e := newTestEngine(t, true, p, Actions{})
	require.Error(t, e.Start(context.Background(), nil))
	assert.Equal(t, 0, e.Len())
	assert.False(t, p.started, "the providers aren't started when the load fails")

	// the rule that doesn't compile
	p = &fakeProvider{policies: []*policy.Policy{behaviour("p", def("bad", "evt.name = 'Nope'"))}}
	e = newTestEngine(t, true, p, Actions{})
	err := e.Start(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Nope")
	assert.Equal(t, 0, e.Len())

	// the provider that can't start
	p = &fakeProvider{startErr: errors.New("watch failed")}
	e = newTestEngine(t, true, p, Actions{})
	require.Error(t, e.Start(context.Background(), nil))
}

func TestEngineReloadsWhenProviderReportsChanges(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p",
		def("reg", "evt.name = 'RegOpenKey' and registry.path imatches ('a*')"))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())

	var (
		mu      sync.Mutex
		reports []*RuleSetReport
	)
	e.OnReload(func(r *RuleSetReport) { mu.Lock(); reports = append(reports, r); mu.Unlock() })
	startEngine(t, e)

	// the approvers consumers obtain from the engine follow the rule set
	b := values(map[Key]string{keyPath: "bcd"})
	assert.False(t, e.Approvers().Approve(event.RegOpenKey, b))

	p.update(nil, behaviour("p",
		def("reg", "evt.name = 'RegOpenKey' and registry.path imatches ('a*')"),
		def("reg2", "evt.name = 'RegOpenKey' and registry.path imatches ('b*')"),
		def("file", "evt.name = 'CreateFile'"),
	))

	waitFor(t, func() bool { return e.Len() == 3 })
	assert.True(t, e.Approvers().Approve(event.RegOpenKey, b))
	mu.Lock()
	require.Len(t, reports, 2) // the initial load and the reload
	assert.Equal(t, 3, reports[1].NumberRules)
	assert.True(t, reports[1].HasFileEvents)
	mu.Unlock()

	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.CreateFile)))
	assert.Len(t, fa.alerts, 1)
}

func TestEngineReloadsOnSignal(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	e := newTestEngine(t, true, p, Actions{})
	reload := startEngine(t, e)

	// the provider changed the policies without notifying the loader
	p.mu.Lock()
	p.policies = []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'"))}
	p.mu.Unlock()
	assert.Equal(t, 1, e.Len())

	reload <- struct{}{}
	waitFor(t, func() bool { return e.Len() == 2 })
}

func TestEngineKeepsRuleSetWhenReloadFails(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())

	var (
		mu     sync.Mutex
		errs   []error
		loaded int
	)
	e.SetRulesetLoadedCallback(func(rs *RuleSet, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		loaded++
	})
	startEngine(t, e)
	before := e.GetRuleSet()
	failures := func() int { mu.Lock(); defer mu.Unlock(); return len(errs) }

	// the invalid rule
	p.update(nil, behaviour("p", def("a", "evt.name = 'CreateFile'"), def("bad", "evt.nnname = 'x'")))
	waitFor(t, func() bool { return failures() == 1 })
	assert.Same(t, before, e.GetRuleSet())

	// the provider failure
	p.update(errors.New("unreachable"), behaviour("p"))
	waitFor(t, func() bool { return failures() == 2 })
	assert.Same(t, before, e.GetRuleSet())

	// duplicate rule identifiers across policies
	p.update(nil, behaviour("p1", def("a", "evt.name = 'CreateFile'")), behaviour("p2", def("a", "evt.name = 'WriteFile'")))
	waitFor(t, func() bool { return failures() == 3 })
	assert.Same(t, before, e.GetRuleSet())

	// the previous rules keep working
	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.CreateFile)))
	assert.Len(t, fa.alerts, 1)

	// and the engine recovers when the policies are fixed
	p.update(nil, behaviour("p", def("a", "evt.name = 'WriteFile'")))
	waitFor(t, func() bool { return e.GetRuleSet() != before })
	require.NoError(t, e.HandleEvent(testutil.MakeEvent(event.WriteFile)))
	assert.Len(t, fa.alerts, 2)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, loaded) // the initial load and the recovery
}

func TestEngineReloadLoopSurvivesPanics(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	e := newTestEngine(t, true, p, Actions{})

	var calls atomic.Int32
	e.OnReload(func(*RuleSetReport) {
		if calls.Add(1) == 2 {
			panic("boom")
		}
	})
	startEngine(t, e)

	p.update(nil, behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'")))
	waitFor(t, func() bool { return calls.Load() == 2 })

	// the loop is still alive after the panic, and the lock is released
	p.update(nil, behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'"), def("c", "evt.name = 'CreateProcess'")))
	waitFor(t, func() bool { return e.Len() == 3 })
}

func TestEngineReloadDiscardsSequenceState(t *testing.T) {
	seq := `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("seq", seq))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())
	startEngine(t, e)

	require.NoError(t, e.HandleEvent(makeEvent(event.CreateProcess, 1)))
	// the rule set built after the reload starts from the clean sequence state
	before := e.GetRuleSet()
	p.update(nil, behaviour("p", def("seq", seq)))
	waitFor(t, func() bool { return e.GetRuleSet() != before })
	require.NoError(t, e.HandleEvent(makeEvent(event.CreateFile, 1)))
	assert.Empty(t, fa.alerts)

	require.NoError(t, e.HandleEvent(makeEvent(event.CreateProcess, 2)))
	require.NoError(t, e.HandleEvent(makeEvent(event.CreateFile, 2)))
	require.Len(t, fa.alerts, 1)

	// all events that participated in the sequence match are marked
	for _, evt := range fa.alerts[0].Events {
		assert.Equal(t, "seq", evt.GetMetaAsString(event.RuleNameKey))
	}
}

func TestEngineHeartbeats(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{
		behaviour("a.yml", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'")),
		behaviour("b.yml", def("c", "evt.name = 'CreateProcess'")),
	}}
	hb := &fakeHeartbeats{}
	e := newTestEngine(t, true, p, Actions{},
		WithHeartbeatSender(hb), WithHeartbeatIntervals(10*time.Millisecond, 20*time.Millisecond))
	startEngine(t, e)

	// the heartbeat is sent when the rules are loaded, and then periodically
	waitFor(t, func() bool { return hb.count() >= 4 })

	last := hb.last()
	assert.Equal(t, 3, last.NumberRules)
	require.Len(t, last.Policies, 2)
	assert.Equal(t, HeartbeatPolicy{Name: "a.yml", Source: "a.yml", Rules: 2}, last.Policies[0])
	assert.Equal(t, 1, last.Policies[1].Rules)
	assert.False(t, last.Time.IsZero())
}

func TestEngineReloadSendsHeartbeatImmediately(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	hb := &fakeHeartbeats{}
	// the period is long, so only the load triggered heartbeats are observed
	e := newTestEngine(t, true, p, Actions{},
		WithHeartbeatSender(hb), WithHeartbeatIntervals(time.Hour, time.Hour))
	startEngine(t, e)

	waitFor(t, func() bool { return hb.count() == 1 })
	assert.Equal(t, 1, hb.last().NumberRules)

	p.update(nil, behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'")))
	waitFor(t, func() bool { return hb.count() == 2 })
	assert.Equal(t, 2, hb.last().NumberRules)
}

func TestEngineStop(t *testing.T) {
	p := &fakeProvider{}
	hb := &fakeHeartbeats{}
	e := newTestEngine(t, true, p, Actions{}, WithHeartbeatSender(hb), WithHeartbeatIntervals(5*time.Millisecond, 5*time.Millisecond))
	startEngine(t, e)

	e.Stop()
	assert.True(t, p.closed)

	// no heartbeats after the engine has stopped
	n := hb.count()
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, n, hb.count())

	// stopping twice is safe
	assert.NotPanics(t, e.Stop)
}

func TestEngineStopsWhenContextIsCancelled(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	e := newTestEngine(t, true, p, Actions{})
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, e.Start(ctx, nil))
	cancel()

	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the engine goroutines should stop when the context is cancelled")
	}
}

func TestEngineConcurrentHandleEventAndReload(t *testing.T) {
	p := &fakeProvider{policies: []*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))}}
	fa := &fakeActions{}
	e := newTestEngine(t, true, p, fa.actions())
	startEngine(t, e)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = e.HandleEvent(testutil.MakeEvent(event.CreateFile))
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		p.update(nil, behaviour("p", def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'WriteFile'")))
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	waitFor(t, func() bool { return e.Len() == 2 })
}
