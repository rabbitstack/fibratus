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
	"fmt"
	"sync"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// def builds the rule definition. The identifier is derived from the name.
func def(name, condition string) *policy.RuleDef {
	return &policy.RuleDef{ID: policy.RuleID("id-" + name), Name: name, Condition: condition}
}

func behaviour(source string, rules ...*policy.RuleDef) *policy.Policy {
	return &policy.Policy{ID: policy.ID(source), Name: source, Source: source, Type: policy.Behaviour, Rules: rules}
}

// collector is the rule set listener that records the matches.
type collector struct {
	mu      sync.Mutex
	matches []RuleMatch
	// stop makes the collector stop the notification of the other listeners
	stop bool
}

func (c *collector) RuleMatch(rule *Rule, events []*event.Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matches = append(c.matches, RuleMatch{Rule: rule, Events: events})
	return !c.stop
}

func (c *collector) take() []RuleMatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.matches
	c.matches = nil
	return m
}

var collectors sync.Map // *RuleSet -> *collector

func mustRuleSet(t *testing.T, matchAll bool, policies ...*policy.Policy) *RuleSet {
	t.Helper()
	rs, err := NewRuleSet(policies, WithMatchAll(matchAll))
	require.NoError(t, err)
	c := &collector{}
	rs.AddListener(c)
	collectors.Store(rs, c)
	return rs
}

// evaluate evaluates the event and returns the matches the listener has recorded.
func evaluate(rs *RuleSet, evt *event.Event) []RuleMatch {
	if rs == nil {
		return nil
	}
	c, ok := collectors.Load(rs)
	if !ok {
		c = &collector{}
		rs.AddListener(c.(*collector))
		collectors.Store(rs, c)
	}
	rs.Evaluate(evt)
	return c.(*collector).take()
}

func names(matches []RuleMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Rule.Name)
	}
	return out
}

func TestRuleSetEvaluate(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p",
		def("cmd", "evt.name = 'CreateProcess' and ps.name = 'cmd.exe'"),
		def("create_file", "evt.name = 'CreateFile'"),
		def("write_or_create", "evt.name in ('WriteFile', 'CreateFile')"),
	))
	require.Equal(t, 3, rs.Len())

	var tests = []struct {
		name     string
		evt      *event.Event
		expected []string
	}{
		{
			"simple rule matches",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "cmd.exe"))),
			[]string{"cmd"},
		},
		{
			"simple rule doesn't match the condition",
			testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "pwsh.exe"))),
			nil,
		},
		{
			"rules are returned in the load order",
			testutil.MakeEvent(event.CreateFile),
			[]string{"create_file", "write_or_create"},
		},
		{
			"rule scoped by multiple types",
			testutil.MakeEvent(event.WriteFile),
			[]string{"write_or_create"},
		},
		{
			"event type with no rules",
			testutil.MakeEvent(event.DeleteFile),
			nil,
		},
		{
			"event nobody is interested in",
			testutil.MakeEvent(event.RegSetValue),
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := evaluate(rs, tt.evt)
			assert.Equal(t, tt.expected, names(matches))
			for _, m := range matches {
				// simple rules match with the evaluated event
				require.Len(t, m.Events, 1)
				assert.Same(t, tt.evt, m.Events[0])
			}
		})
	}
}

func TestRuleSetMatchAllStrategy(t *testing.T) {
	policies := []*policy.Policy{behaviour("p",
		def("first", "evt.name = 'CreateFile'"),
		def("second", "evt.name = 'CreateFile'"),
		def("third", "evt.name = 'CreateFile' and evt.category = 'file'"),
	)}

	rs := mustRuleSet(t, true, policies...)
	assert.True(t, rs.MatchAll())
	assert.Equal(t, []string{"first", "second", "third"}, names(evaluate(rs, testutil.MakeEvent(event.CreateFile))))

	rs = mustRuleSet(t, false, policies...)
	assert.False(t, rs.MatchAll())
	assert.Equal(t, []string{"first"}, names(evaluate(rs, testutil.MakeEvent(event.CreateFile))))
}

func TestRuleSetIndexing(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p",
		def("by_type", "evt.name = 'CreateFile'"),
		def("by_types", "evt.name in ('CreateFile', 'WriteFile')"),
		def("by_category_condition", "evt.name = 'RegSetValue' and evt.category = 'registry'"),
	))

	assert.Equal(t, 2, rs.GetBucket(event.CreateFile).Len())
	assert.Equal(t, 1, rs.GetBucket(event.WriteFile).Len())
	assert.Equal(t, 0, rs.GetBucket(event.CreateProcess).Len())
	// the category condition doesn't index the rule
	assert.Equal(t, 1, rs.GetBucket(event.RegSetValue).Len())
	assert.Equal(t, 0, rs.GetBucket(event.RegCreateKey).Len())

	assert.NotNil(t, rs.GetRuleByID("id-by_type"))
	assert.Nil(t, rs.GetRuleByID("id-unknown"))
	assert.Len(t, rs.GetRules(), 3)
	assert.Len(t, rs.GetPolicies(), 1)
	//assert.False(t, rs.HasSequences())
}

func TestRuleSetDiscardsUnscopedRules(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p",
		def("unscoped", "ps.name = 'cmd.exe'"),
		def("not_equal", "evt.name != 'CreateFile'"),
		def("category_only", "evt.category = 'file'"),
		def("contradicting", "evt.name = 'CreateFile' and evt.name = 'WriteFile'"),
		def("scoped", "evt.name = 'CreateFile'"),
	))
	assert.Equal(t, 1, rs.Len())
	assert.Equal(t, []string{"scoped"}, names(evaluate(rs, testutil.MakeEvent(event.CreateFile))))
	assert.Nil(t, evaluate(rs, testutil.MakeEvent(event.DeleteFile)))

	discarded := rs.Report().Discarded
	require.Len(t, discarded, 4)
	var got []string
	for _, d := range discarded {
		got = append(got, d.Name)
		assert.Equal(t, "p", d.Source)
		assert.NotEmpty(t, d.Reason)
	}
	assert.Equal(t, []string{"unscoped", "not_equal", "category_only", "contradicting"}, got)
	assert.Contains(t, discarded[2].Reason, "not scoped by the event type")
	assert.Contains(t, discarded[3].Reason, "contradicting")
	assert.Nil(t, evaluate(rs, testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "cmd.exe")))))
}

func TestRuleSetSkipsDisabledAndSignatureRules(t *testing.T) {
	disabled := false
	off := def("off", "evt.name = 'CreateFile'")
	off.Enabled = &disabled

	sig := behaviour("sig", def("signature_rule", "evt.name = 'CreateFile'"))
	sig.Type = policy.Signature

	rs := mustRuleSet(t, true, behaviour("p", off, def("on", "evt.name = 'WriteFile'")), sig)
	assert.Equal(t, 1, rs.Len())
	assert.Equal(t, "on", rs.GetRules()[0].Name)
}

func TestRuleSetMacrosAreSharedAcrossPolicies(t *testing.T) {
	macros := &policy.Policy{
		Name: "macros", Source: "macros.yml", Type: policy.Behaviour,
		Macros: []*policy.MacroDef{
			{ID: "spawn_process", Expression: "evt.name = 'CreateProcess'"},
			{ID: "shells", Values: []string{"cmd.exe", "pwsh.exe"}},
		},
	}
	rs := mustRuleSet(t, true, macros, behaviour("rule.yml", def("shell", "spawn_process and ps.name in shells")))

	assert.Equal(t, 2, rs.GetMacros().Len())
	assert.Equal(t, []string{"shell"}, names(evaluate(rs,
		testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "pwsh.exe"))))))
	assert.Nil(t, evaluate(rs, testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "notepad.exe")))))
}

func TestRuleSetErrors(t *testing.T) {
	var tests = []struct {
		name     string
		policies []*policy.Policy
		errs     []string
	}{
		{
			"syntax error",
			[]*policy.Policy{behaviour("p", def("bad", "evt.nnname = 'CreateFile'"))},
			[]string{`syntax error in rule "bad"`},
		},
		{
			"unknown macro",
			[]*policy.Policy{behaviour("p", def("bad", "no_such_macro and evt.name = 'CreateFile'"))},
			[]string{`syntax error in rule "bad"`},
		},
		{
			"unknown event name",
			[]*policy.Policy{behaviour("p", def("bad", "evt.name = 'CreateFyle'"))},
			[]string{`invalid event name "CreateFyle"`},
		},
		{
			"unknown event name in a list",
			[]*policy.Policy{behaviour("p", def("bad", "evt.name in ('CreateFile', 'Nope')"))},
			[]string{`invalid event name "Nope"`},
		},
		{
			"unknown category",
			[]*policy.Policy{behaviour("p", def("bad", "evt.name = 'CreateFile' and evt.category = 'filez'"))},
			[]string{`invalid event category "filez"`},
		},
		{
			"duplicate id",
			[]*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"), &policy.RuleDef{
				ID: "id-a", Name: "b", Condition: "evt.name = 'CreateFile'",
			})},
			[]string{"uses duplicate id id-a"},
		},
		{
			"all invalid rules are reported",
			[]*policy.Policy{behaviour("p",
				def("one", "evt.name = 'Nope'"),
				def("good", "evt.name = 'CreateFile'"),
				def("two", "evt.name = 'CreateFile' and evt.category = 'nope'"),
			)},
			[]string{`invalid event name "Nope"`, `invalid event category "nope"`},
		},
		{
			"macro cycle",
			[]*policy.Policy{{
				Name: "m", Type: policy.Behaviour,
				Macros: []*policy.MacroDef{{ID: "a", Expression: "b"}, {ID: "b", Expression: "a"}},
			}},
			[]string{"macro cycle detected"},
		},
		{
			"malformed minimum engine version is ignored in dev builds",
			[]*policy.Policy{behaviour("p", &policy.RuleDef{
				ID: "x", Name: "x", Condition: "evt.name = 'CreateFile'", MinEngineVersion: "not-a-version",
			})},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs, err := NewRuleSet(tt.policies)
			if len(tt.errs) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Nil(t, rs)
			for _, e := range tt.errs {
				assert.Contains(t, err.Error(), e)
			}
		})
	}
}

func TestEmptyRuleSet(t *testing.T) {
	rs, err := NewRuleSet(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, rs.Len())
	assert.Nil(t, evaluate(rs, testutil.MakeEvent(event.CreateFile)))
	assert.Equal(t, 0, rs.Report().NumberRules)

	var nilRS *RuleSet
	assert.Nil(t, evaluate(nilRS, testutil.MakeEvent(event.CreateFile)))
	assert.Equal(t, 0, nilRS.Len())
	assert.NotNil(t, nilRS.Report())
	// the nil approvers approve everything
	assert.True(t, nilRS.Approvers().Approve(event.RegOpenKey, nil))
}

func TestRuleSetKeepsRulesIsolated(t *testing.T) {
	// rules from different policy sources keep their source
	rs := mustRuleSet(t, true,
		behaviour("a.yml", def("a", "evt.name = 'CreateFile'")),
		behaviour("b.yml", def("b", "evt.name = 'CreateFile'")),
	)
	assert.Equal(t, "a.yml", rs.GetRuleByID("id-a").Source)
	assert.Equal(t, "b.yml", rs.GetRuleByID("id-b").Source)
}

func TestRuleSetManyRulesKeepLoadOrder(t *testing.T) {
	var rules []*policy.RuleDef
	for i := 0; i < 20; i++ {
		cond := "evt.name = 'CreateFile'"
		if i%2 == 1 {
			cond = "evt.name in ('CreateFile', 'WriteFile')"
		}
		rules = append(rules, def(fmt.Sprintf("r%02d", i), cond))
	}
	rs := mustRuleSet(t, true, behaviour("p", rules...))

	matches := evaluate(rs, testutil.MakeEvent(event.CreateFile))
	require.Len(t, matches, 20)
	for i, m := range matches {
		assert.Equal(t, fmt.Sprintf("r%02d", i), m.Rule.Name)
	}
}

func TestRuleSetReport(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p",
		def("proc", "evt.name = 'CreateProcess'"),
		def("file", "evt.name in ('CreateFile', 'WriteFile')"),
		def("net", "evt.name = 'Connect'"),
		def("registry", "evt.name in ('RegSetValue', 'RegOpenKey')"),
		def("dns", "evt.name = 'QueryDns'"),
		def("audit", "evt.name = 'OpenProcess'"),
		def("vamap", "evt.name = 'MapViewFile'"),
	))
	info := rs.Report()

	assert.Equal(t, 7, info.NumberRules)
	assert.Empty(t, info.Discarded)
	assert.True(t, info.HasProcEvents)
	assert.True(t, info.HasFileEvents)
	assert.True(t, info.HasNetworkEvents)
	assert.True(t, info.HasRegistryEvents)
	assert.True(t, info.HasDNSEvents)
	assert.True(t, info.HasAuditAPIEvents)
	assert.True(t, info.HasVAMapEvents)
	assert.False(t, info.HasThreadEvents)
	assert.False(t, info.HasModuleEvents)
	assert.False(t, info.HasMemEvents)

	assert.True(t, info.ContainsEvent(event.CreateProcess))
	assert.True(t, info.ContainsEvent(event.WriteFile))
	assert.True(t, info.ContainsEvent(event.Connect))
	assert.True(t, info.ContainsEvent(event.RegSetValue))
	assert.True(t, info.ContainsEvent(event.RegOpenKey))
	assert.False(t, info.ContainsEvent(event.CreateThread))
	assert.NotEmpty(t, info.String())
}

func TestReportIgnoresCategoryConditions(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p", def("r", "evt.category = 'file' and evt.name in ('CreateFile', 'CreateProcess')")))
	report := rs.Report()
	// the category condition doesn't narrow the event types down
	assert.True(t, report.ContainsEvent(event.CreateFile))
	assert.True(t, report.ContainsEvent(event.CreateProcess))
	assert.True(t, report.HasProcEvents)
	// but it still has to be satisfied by the evaluated event
	assert.Nil(t, evaluate(rs, testutil.MakeEvent(event.CreateProcess)))
}

func TestReportCoverage(t *testing.T) {
	small := mustRuleSet(t, true, behaviour("p", def("a", "evt.name = 'CreateFile'"))).Report()
	big := mustRuleSet(t, true, behaviour("p",
		def("a", "evt.name = 'CreateFile'"),
		def("b", "evt.name = 'CreateProcess'"),
	)).Report()

	assert.True(t, big.Covers(small))
	assert.False(t, small.Covers(big))
	assert.Equal(t, []event.Type{event.CreateProcess}, small.Missing(big))
	assert.Empty(t, small.Missing(nil))

	var nilInfo *RuleSetReport
	assert.False(t, nilInfo.ContainsEvent(event.CreateFile))
}

type listenerFunc func(rule *Rule, events []*event.Event) bool

func (f listenerFunc) RuleMatch(rule *Rule, events []*event.Event) bool { return f(rule, events) }

func TestRuleSetListeners(t *testing.T) {
	rs, err := NewRuleSet([]*policy.Policy{behaviour("p",
		def("a", "evt.name = 'CreateFile'"),
		def("b", "evt.name = 'CreateFile' and file.name = 'x'"),
	)}, WithMatchAll(true))
	require.NoError(t, err)

	var calls []string
	rs.AddListener(listenerFunc(func(r *Rule, evts []*event.Event) bool {
		calls = append(calls, "first:"+r.Name)
		return true
	}))
	// the listener that returns false stops the notification of the next listeners
	rs.AddListener(listenerFunc(func(r *Rule, evts []*event.Event) bool {
		calls = append(calls, "second:"+r.Name)
		return false
	}))
	rs.AddListener(listenerFunc(func(r *Rule, evts []*event.Event) bool {
		calls = append(calls, "third:"+r.Name)
		return true
	}))

	evt := testutil.MakeEvent(event.CreateFile)
	assert.True(t, rs.Evaluate(evt))
	// the rule `b` doesn't match, since the event has no file name
	assert.Equal(t, []string{"first:a", "second:a"}, calls)

	// no match, no notification
	calls = nil
	assert.False(t, rs.Evaluate(testutil.MakeEvent(event.WriteFile)))
	assert.Empty(t, calls)
}

func TestRuleSetEvaluateWithoutListeners(t *testing.T) {
	rs, err := NewRuleSet([]*policy.Policy{behaviour("p", def("a", "evt.name = 'CreateFile'"))})
	require.NoError(t, err)
	assert.True(t, rs.Evaluate(testutil.MakeEvent(event.CreateFile)))
	assert.False(t, rs.Evaluate(testutil.MakeEvent(event.WriteFile)))
}

func TestRuleSetNotifiesAllMatchesOnlyWithMatchAll(t *testing.T) {
	for _, matchAll := range []bool{true, false} {
		rs, err := NewRuleSet([]*policy.Policy{behaviour("p",
			def("a", "evt.name = 'CreateFile'"), def("b", "evt.name = 'CreateFile'"))}, WithMatchAll(matchAll))
		require.NoError(t, err)
		var n int
		rs.AddListener(listenerFunc(func(*Rule, []*event.Event) bool { n++; return true }))
		assert.True(t, rs.Evaluate(testutil.MakeEvent(event.CreateFile)))
		if matchAll {
			assert.Equal(t, 2, n)
		} else {
			assert.Equal(t, 1, n)
		}
	}
}

func TestRuleSetAccessors(t *testing.T) {
	macros := &policy.Policy{
		Name: "macros", Source: "m.yml", Type: policy.Behaviour,
		Macros: []*policy.MacroDef{{ID: "spawn", Expression: "evt.name = 'CreateProcess'"}},
	}
	rs := mustRuleSet(t, true, macros, behaviour("p",
		def("proc", "spawn and ps.name = 'cmd.exe'"),
		def("file", "evt.name in ('CreateFile', 'WriteFile') and file.path imatches ('a*')"),
	))

	assert.Equal(t, []policy.RuleID{"id-proc", "id-file"}, rs.ListRuleIDs())
	assert.Equal(t, []policy.MacroID{"spawn"}, rs.ListMacroIDs())
	require.Len(t, rs.GetRules(), 2)
	assert.Equal(t, "proc", rs.GetRules()[0].Name)
	assert.Equal(t, "file", rs.GetRuleByID("id-file").Name)
	assert.Nil(t, rs.GetRuleByID("nope"))
	assert.Len(t, rs.GetRuleMap(), 2)
	assert.Len(t, rs.GetPolicies(), 2)

	assert.True(t, rs.HasRulesForEventType(event.CreateProcess))
	assert.True(t, rs.HasRulesForEventType(event.WriteFile))
	assert.False(t, rs.HasRulesForEventType(event.RegSetValue))
	assert.Equal(t, 1, rs.GetBucket(event.CreateProcess).Len())

	assert.Equal(t, []string{"evt.name", "file.path", "ps.name"}, rs.ListFields())

	// the approvers can be computed for the other event source capabilities
	caps := ApproverCaps{Keys: map[event.Type][]Key{event.CreateFile: {filePath}}}
	a := rs.GetApprovers(caps)
	assert.Equal(t, []event.Type{event.CreateFile}, a.Types())

	// nil rule set is safe to use
	var nilRS *RuleSet
	assert.Empty(t, nilRS.ListRuleIDs())
	assert.Empty(t, nilRS.GetRules())
	assert.Nil(t, nilRS.GetRuleByID("x"))
	assert.False(t, nilRS.HasRulesForEventType(event.CreateFile))
	assert.Nil(t, nilRS.GetBucket(event.CreateFile))
	assert.Empty(t, nilRS.ListFields())
	assert.NotNil(t, nilRS.Report())
}

func TestRuleSetIncrementalConstruction(t *testing.T) {
	rs := NewEmptyRuleSet(WithMatchAll(true))
	assert.Equal(t, 0, rs.Len())
	assert.False(t, rs.Evaluate(testutil.MakeEvent(event.CreateFile)))

	require.NoError(t, rs.AddMacro(&policy.MacroDef{ID: "files", Values: []string{"a.exe", "b.exe"}}))
	require.NoError(t, rs.AddRules([]*policy.RuleDef{
		def("a", "evt.name = 'CreateFile' and file.name in files"),
		def("b", "evt.name = 'WriteFile'"),
	}, "x.yml"))
	assert.Equal(t, 2, rs.Len())
	assert.Equal(t, "x.yml", rs.GetRuleByID("id-a").Source)
	assert.Equal(t, 2, rs.Report().NumberRules)

	// the report follows the rules added after it was computed
	require.NoError(t, rs.AddRule(def("c", "evt.name = 'CreateProcess'"), "x.yml"))
	assert.Equal(t, 3, rs.Report().NumberRules)
	assert.True(t, rs.Report().HasProcEvents)

	// the failing rules don't prevent adding the others
	err := rs.AddRules([]*policy.RuleDef{def("a", "evt.name = 'CreateFile'"), def("d", "evt.name = 'RegSetValue'")}, "x.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate id")
	assert.Equal(t, 4, rs.Len())

	// invalid macros leave the macro store untouched
	err = rs.AddMacros([]*policy.MacroDef{{ID: "x", Expression: "y"}, {ID: "y", Expression: "x"}})
	require.Error(t, err)
	assert.Equal(t, []policy.MacroID{"files"}, rs.ListMacroIDs())
}
