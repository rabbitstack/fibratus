/*
 * Copyright 2026 by Mostafa Moradian
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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compileApprover(t *testing.T, expr string) Filter {
	t.Helper()
	return mustCompileApprover(t, expr)
}

func mustCompileApprover(tb testing.TB, expr string) Filter {
	tb.Helper()
	f := New(expr, &config.Config{
		EventSource: config.EventSourceConfig{
			EnableFileIOEvents: true,
			EnableNetEvents:    true,
			EnableMemEvents:    true,
		},
		Filters: &config.Filters{},
	})
	require.NoError(tb, f.Compile(), expr)
	return f
}

func TestExtractEqualityListPrefix(t *testing.T) {
	f := compileApprover(t, "evt.name = 'openat' and file.path startswith '/tmp' and ps.pid in (1, 42)")
	ex := f.(ApproverProvider).ApproverExtraction()
	require.False(t, ex.Unsupported)
	assert.Equal(t, []event.Type{event.Openat}, ex.Types)
	assert.ElementsMatch(t, []uint64{1, 42}, ex.PIDs)
	assert.Equal(t, []string{"/tmp"}, ex.FilePrefix)
}

func TestExtractPortList(t *testing.T) {
	f := compileApprover(t, "evt.name = 'connect' and net.dport in (80, 443)")
	ex := f.(ApproverProvider).ApproverExtraction()
	require.False(t, ex.Unsupported)
	assert.Equal(t, []uint16{80, 443}, ex.Ports)
}

func TestExtractUnsupportedShapesDefaultAllow(t *testing.T) {
	cases := []string{
		"evt.name = 'openat' and file.path != '/etc/passwd'",
		"evt.name = 'openat' and not (file.path = '/etc/passwd')",
		"evt.name = 'openat' and (ps.pid = 1 or file.path = '/tmp/x')",
		"evt.name = 'openat' and file.path matches '/tmp/*'",
		"evt.name = 'openat' and ps.pid > 1",
		"evt.name = 'openat' and lower(file.path) = '/tmp/x'",
		`sequence
|evt.name = 'execve'|
|evt.name = 'connect'|`,
	}
	for _, expr := range cases {
		f := compileApprover(t, expr)
		plan := PlanFromFilter(f)
		assert.True(t, plan.Policy(event.Openat).DefaultAllow || plan.Policy(event.Connect).DefaultAllow || plan.Policy(event.Execve).DefaultAllow, expr)
	}

	orPlan := PlanFromFilter(compileApprover(t, "evt.name = 'openat' and (ps.pid = 1 or file.path = '/tmp/x')"))
	assert.True(t, orPlan.Policy(event.Openat).DefaultAllow)

	seqPlan := PlanFromFilter(compileApprover(t, `sequence
|evt.name = 'execve'|
|evt.name = 'connect'|`))
	assert.True(t, seqPlan.Policy(event.Execve).DefaultAllow)
	assert.True(t, seqPlan.Policy(event.Connect).DefaultAllow)
}

// ps.name is snapshot state while the kernel can only read the live task comm,
// so a process name predicate must never narrow the in-kernel prefilter.
func TestProcessNameIsNotExtractable(t *testing.T) {
	plan := PlanFromFilter(compileApprover(t, "evt.name = 'openat' and ps.name = 'bash'"))
	assert.True(t, plan.Policy(event.Openat).DefaultAllow)

	mixed := PlanFromFilter(compileApprover(t, "evt.name = 'openat' and ps.name = 'bash' and file.path startswith '/tmp'"))
	assert.True(t, mixed.Policy(event.Openat).DefaultAllow)
}

func TestExtractMatchesTrailingStar(t *testing.T) {
	f := compileApprover(t, "evt.name = 'openat' and file.path matches ('/tmp/*', '/var/tmp/*')")
	ex := f.(ApproverProvider).ApproverExtraction()
	require.False(t, ex.Unsupported)
	assert.Equal(t, []string{"/tmp/", "/var/tmp/"}, ex.FilePrefix)

	plan := PlanFromFilter(f)
	assert.True(t, plan.Allows(Sample{Type: event.Openat, Filename: "/tmp/dropper"}))
	assert.True(t, plan.Allows(Sample{Type: event.Openat, Filename: "/tmp/a/b/c"}))
	assert.True(t, plan.Allows(Sample{Type: event.Openat, Filename: "/var/tmp/x"}))
	assert.False(t, plan.Allows(Sample{Type: event.Openat, Filename: "/etc/passwd"}))
}

// A trailing '*' spans every remaining byte, separators included, so rewriting
// it to a prefix is exact rather than merely conservative.
func TestTrailingStarRewriteMatchesOperator(t *testing.T) {
	paths := []string{"/tmp/x", "/tmp/a/b/c", "/tmp/", "/tmpfoo", "/etc/passwd", ""}
	for _, pattern := range []string{"/tmp/*", "/tmp/**", "/etc/passwd", "*"} {
		literal, prefix, ok := globAsPrefix(pattern)
		require.True(t, ok, pattern)
		pol := TypePolicy{RequireFilename: true}
		switch {
		case literal != "":
			pol.FileExact = []string{literal}
		case prefix != "":
			pol.FilePrefix = []string{prefix}
		default:
			continue // '*' constrains nothing
		}
		for _, path := range paths {
			assert.Equal(t, wildcard.Match(pattern, path, true), matchFilename(pol, path),
				"pattern=%q path=%q", pattern, path)
		}
	}
}

// Patterns that are not reducible to a prefix have no kernel equivalent, so
// they must widen to default-allow rather than be approximated.
func TestNonPrefixGlobsAreDefaultAllow(t *testing.T) {
	for _, expr := range []string{
		"evt.name = 'openat' and file.path matches '/tmp/*/evil'",
		"evt.name = 'openat' and file.path matches '*.so'",
		"evt.name = 'openat' and file.path matches '/tmp/?vil'",
		"evt.name = 'openat' and file.path matches ('/tmp/*', '*.so')",
		"evt.name = 'openat' and file.path imatches '/TMP/*'",
	} {
		plan := PlanFromFilter(compileApprover(t, expr))
		assert.True(t, plan.Policy(event.Openat).DefaultAllow, expr)
	}
}

func TestVacuousStarDoesNotConstrain(t *testing.T) {
	plan := PlanFromFilter(compileApprover(t, "evt.name = 'openat' and file.path matches '*'"))
	assert.True(t, plan.Policy(event.Openat).DefaultAllow)
}

func TestBuildPlanIntersectsRequiredFields(t *testing.T) {
	pid := compileApprover(t, "evt.name = 'openat' and ps.pid = 7")
	path := compileApprover(t, "evt.name = 'openat' and file.path startswith '/tmp'")
	mixed := BuildApproverPlan([]Filter{pid, path})
	assert.True(t, mixed.Policy(event.Openat).DefaultAllow, "different required fields cannot be ANDed across rules")

	a := compileApprover(t, "evt.name = 'openat' and file.path startswith '/tmp'")
	b := compileApprover(t, "evt.name = 'openat' and file.path startswith '/var'")
	union := BuildApproverPlan([]Filter{a, b})
	pol := union.Policy(event.Openat)
	require.False(t, pol.DefaultAllow)
	assert.True(t, pol.RequireFilename)
	assert.ElementsMatch(t, []string{"/tmp", "/var"}, pol.FilePrefix)
}

func TestAllowsNeverFalseNegative(t *testing.T) {
	f := compileApprover(t, "evt.name = 'openat' and file.path startswith '/tmp' and ps.pid = 42")
	plan := PlanFromFilter(f)

	keep := Sample{Type: event.Openat, PID: 42, Filename: "/tmp/payload"}
	drop := Sample{Type: event.Openat, PID: 7, Filename: "/etc/passwd"}
	assert.True(t, plan.Allows(keep))
	assert.False(t, plan.Allows(drop))
	assert.True(t, plan.Allows(Sample{Type: event.Openat, PID: 42, Filename: "/tmp", Truncated: true}))
}

func TestUnionCLIAndRules(t *testing.T) {
	rules := PlanFromFilter(compileApprover(t, "evt.name = 'connect' and net.dport in (80, 443)"))
	cli := PlanFromFilter(compileApprover(t, "evt.name = 'connect' and net.dport = 443"))
	combined := Union(rules, cli)
	pol := combined.Policy(event.Connect)
	require.False(t, pol.DefaultAllow)
	assert.True(t, pol.RequirePort)
	assert.ElementsMatch(t, []uint16{80, 443}, pol.Ports)
	assert.True(t, combined.Allows(Sample{Type: event.Connect, Port: 80}))
	assert.True(t, combined.Allows(Sample{Type: event.Connect, Port: 443}))
	assert.False(t, combined.Allows(Sample{Type: event.Connect, Port: 22}))
}
