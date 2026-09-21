//go:build linux

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

package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/require"
)

func TestCompilerLinuxRule(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "execve.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Linux process execution
id: 4d17dc44-cc9f-4f13-9a31-23c6529ff46e
version: 1.0.0
min-engine-version: 3.0.0
condition: evt.name = 'execve' and ps.name = 'bash'
`), 0o600))

	cfg := &config.Config{
		Filters: &config.Filters{
			Rules: config.Rules{FromPaths: []string{rule}},
		},
	}
	filters, result, err := newCompiler(ps.NewSnapshotter(), cfg).compile()
	require.NoError(t, err)
	require.Len(t, filters, 1)
	require.NotNil(t, result)
	require.True(t, result.HasProcEvents)
}

func TestCompilerExtractableApproverPlan(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "openat.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Temporary file open
id: 7c1c2d3e-4f5a-6789-abcd-ef0123456789
version: 1.0.0
min-engine-version: 3.0.0
condition: evt.name = 'openat' and file.path startswith '/tmp'
`), 0o600))

	cfg := &config.Config{
		EventSource: config.EventSourceConfig{EnableFileIOEvents: true},
		Filters: &config.Filters{
			Rules: config.Rules{FromPaths: []string{rule}},
		},
	}
	c := newCompiler(ps.NewSnapshotter(), cfg)
	_, result, err := c.compile()
	require.NoError(t, err)
	require.NotNil(t, result)
	pol := c.ApproverPlan().Policy(event.Openat)
	require.False(t, pol.DefaultAllow)
	require.True(t, pol.RequireFilename)
	require.Equal(t, []string{"/tmp"}, pol.FilePrefix)
}

func TestCompilerShippedLinuxRules(t *testing.T) {
	cfg := newLinuxConfig(filepath.Join("..", "..", "rules", "linux", "*.yml"))
	c := newCompiler(ps.NewSnapshotter(), cfg)
	filters, result, err := c.compile()
	require.NoError(t, err)
	require.NotEmpty(t, filters)
	require.NotNil(t, result)
	require.True(t, result.HasProcEvents)
	require.True(t, result.HasNetworkEvents)

	// every shipped rule carries the labels the rule validator warns about
	for f := range filters {
		for _, label := range []string{"tactic.id", "tactic.name", "tactic.ref", "technique.id", "technique.name", "technique.ref"} {
			require.True(t, f.HasLabel(label), "%s is missing the %s label", f.Name, label)
		}
	}

	plan := c.ApproverPlan()
	require.True(t, plan.Policy(event.Execve).DefaultAllow)
	require.True(t, plan.Policy(event.Connect).DefaultAllow)
	require.True(t, plan.Policy(event.Ptrace).DefaultAllow)
	require.True(t, plan.Policy(event.Kill).DefaultAllow)
}

// The approver scopes a sequence rule to the event names and categories in its
// string fields, on the assumption that the engine indexes the sequence by that
// same set and so never evaluates a stage against any other type. Pin it here:
// if indexing ever widens, the approver would under-block and drop events a
// sequence stage needs.
func TestEngineIndexesSequenceByStringFieldTypes(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "sequence.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Execve then unscoped stage
id: 8e2f1a5b-3c4d-4e6f-8a9b-0c1d2e3f4a5b
version: 1.0.0
min-engine-version: 3.0.0
condition: >
  sequence
  maxspan 1m
    |evt.name = 'execve'|
    |ps.pid = 5|
`), 0o600))

	cfg := newLinuxConfig(rule)
	e := NewEngine(ps.NewSnapshotter(), cfg)
	_, err := e.Compile()
	require.NoError(t, err)

	require.Len(t, e.filters.types[event.Execve], 1, "sequence must be indexed under execve")
	for _, typ := range event.All() {
		if typ == event.Execve {
			continue
		}
		require.Empty(t, e.filters.types[typ], "sequence must not be indexed under %s", typ)
	}
	require.Empty(t, e.filters.categories, "sequence names no category")
}

func TestCompilerSharedSemanticFixtures(t *testing.T) {
	cfg := newLinuxConfig("_fixtures/shared/*.yml")
	filters, result, err := newCompiler(ps.NewSnapshotter(), cfg).compile()
	require.NoError(t, err)
	require.Len(t, filters, 2)
	require.NotNil(t, result)
}

func TestCompilerRejectsWindowsEventNames(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "windows.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Windows process execution
id: 5d17dc44-cc9f-4f13-9a31-23c6529ff46e
version: 1.0.0
min-engine-version: 3.0.0
condition: evt.name = 'CreateProcess'
`), 0o600))

	cfg := &config.Config{
		Filters: &config.Filters{
			Rules: config.Rules{FromPaths: []string{rule}},
		},
	}
	_, _, err := newCompiler(ps.NewSnapshotter(), cfg).compile()
	require.EqualError(t, err, ErrUnknownEventName("Windows process execution", "CreateProcess").Error())
}

func TestCompilerRejectsDeprecatedFields(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "kevt.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Deprecated field
id: 6d17dc44-cc9f-4f13-9a31-23c6529ff46e
version: 1.0.0
min-engine-version: 3.0.0
condition: kevt.name = 'execve'
`), 0o600))

	cfg := &config.Config{
		Filters: &config.Filters{
			Rules: config.Rules{FromPaths: []string{rule}},
		},
	}
	_, _, err := newCompiler(ps.NewSnapshotter(), cfg).compile()
	require.Error(t, err)
}
