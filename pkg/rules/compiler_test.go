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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompile(t *testing.T) {
	c := newCompiler(new(ps.SnapshotterMock), newConfig("_fixtures/default/*.yml"))
	filters, rs, err := c.compile()
	require.NoError(t, err)
	require.NotNil(t, rs)
	require.Len(t, filters, 6)

	assert.True(t, rs.HasModuleEvents)
	assert.True(t, rs.HasProcEvents)
	assert.False(t, rs.HasMemEvents)
	assert.False(t, rs.HasAuditAPIEvents)
	assert.True(t, rs.HasDNSEvents)
	assert.Contains(t, rs.UsedEvents, event.CreateProcess)
	assert.Contains(t, rs.UsedEvents, event.LoadModule)
	assert.Contains(t, rs.UsedEvents, event.QueryDNS)
	assert.Contains(t, rs.UsedEvents, event.ConnectTCPv4)
	assert.Contains(t, rs.UsedEvents, event.ConnectTCPv6)
}

func TestCompileMinEngineVersion(t *testing.T) {
	var tests = []struct {
		rules string
		ver   string
		e     string
	}{
		{"_fixtures/min_engine_version/fail/*.yml", "2.0.0", `rule "accept events where source port = 44123" needs engine version [2.2.0] but current version is [2.0.0]`},
		{"_fixtures/min_engine_version/ok/*.yml", "2.0.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.rules, func(t *testing.T) {
			c := newCompiler(new(ps.SnapshotterMock), newConfig(tt.rules))
			version.Set(tt.ver)
			_, _, err := c.compile()
			if err != nil && tt.e == "" {
				require.Error(t, err)
			}
			if err != nil {
				require.EqualError(t, err, tt.e)
			}
		})
	}
}

func TestCompileEventCategoryFieldNames(t *testing.T) {
	var tests = []struct {
		rules string
		err   error
	}{
		{"_fixtures/field_values/correct_event_name_field.yml", nil},
		{"_fixtures/field_values/incorrect_event_name_field.yml", ErrUnknownEventName("match https connections", "RecvTcp4")},
		{"_fixtures/field_values/incorrect_event_name_in_operator.yml", ErrUnknownEventName("match https connections", "CreateProc")},
		{"_fixtures/field_values/correct_category_name_field.yml", nil},
		{"_fixtures/field_values/incorrect_category_name_field.yml", ErrUnknownCategoryName("match https connections", "network")},
	}

	for _, tt := range tests {
		t.Run(tt.rules, func(t *testing.T) {
			c := newCompiler(new(ps.SnapshotterMock), newConfig(tt.rules))
			_, _, err := c.compile()
			if err != nil && tt.err != nil {
				require.Error(t, err)
			}
			if err != nil {
				require.EqualError(t, err, tt.err.Error())
			}
		})
	}
}

func TestVisitApproverPredicatesRegistryEvents(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "RegSetValue does not match",
			expr: "evt.name = 'RegSetValue'",
			want: false,
		},
		{
			name: "RegOpenKey matches",
			expr: "evt.name = 'RegOpenKey'",
			want: true,
		},
		{
			name: "CreateProcess does not match",
			expr: "evt.name = 'CreateProcess'",
			want: false,
		},
		{
			name: "RegOpenKey event nested in AND matches",
			expr: `evt.name = 'RegOpenKey' and registry.path imatches ('HKEY_LOCAL_MACHINE\\SYSTEM\\*')`,
			want: true,
		},
		{
			name: "Registry event nested in paren matches",
			expr: "(evt.name = 'RegOpenKey')",
			want: true,
		},
	}

	c := newCompiler(new(ps.SnapshotterMock), newConfig("_fixtures/default/*.yml"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ql.NewParser(tt.expr)
			n, err := p.ParseExpr()
			require.NoError(t, err)
			got := c.referencesApproverEvents(n)
			if got != tt.want {
				t.Errorf("registry approver predicates: %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVisitApproverPredicatesCreateFile(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "CreateFile with OPEN operation matches",
			expr: "evt.name = 'CreateFile' and file.operation = 'OPEN'",
			want: true,
		},
		{
			name: "CreateFile without file.operation does not match",
			expr: "evt.name = 'CreateFile'",
			want: false,
		},
		{
			name: "CreateFile with non-OPEN operation does not match",
			expr: "evt.name = 'CreateFile' and file.operation = 'CREATE'",
			want: false,
		},
		{
			name: "file.operation OPEN without CreateFile does not match",
			expr: "file.operation = 'OPEN'",
			want: false,
		},
		{
			name: "CreateFile and OPEN in separate OR branches does not match",
			expr: "evt.name = 'CreateFile' or file.operation = 'OPEN'",
			want: false,
		},
		{
			name: "CreateFile with OPEN nested in paren matches",
			expr: "evt.name = 'CreateFile' and (file.operation = 'OPEN')",
			want: true,
		},
		{
			name: "CreateFile with OPEN and extra conditions matches",
			expr: "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.path imatches '?:\\\\Windows\\\\*'",
			want: true,
		},
	}

	c := newCompiler(new(ps.SnapshotterMock), newConfig("_fixtures/default/*.yml"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ql.NewParser(tt.expr)
			n, err := p.ParseExpr()
			require.NoError(t, err)
			got := c.referencesApproverEvents(n)
			if got != tt.want {
				t.Errorf("file approver predicates: %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccumulatedApproverPredicates(t *testing.T) {
	tests := []struct {
		name            string
		expr            string
		wantKeys        map[string][]string
		wantPaths       map[string][]string
		wantExtensions  map[string][]string
		wantExecutables map[string][]string
		wantBases       map[string][]string
	}{
		{
			name: "extracts registry key path with imatches",
			expr: "evt.name = 'RegOpenKey' and registry.path imatches 'HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\*'",
			wantKeys: map[string][]string{
				"IMATCHES": {`hkey_local_machine\system\*`},
			},
		},
		{
			name: "extracts file path with imatches",
			expr: "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.path imatches 'C:\\\\Windows\\\\*'",
			wantPaths: map[string][]string{
				"IMATCHES": {`c:\windows\*`},
			},
		},
		{
			name: "negated registry path is not extracted",
			expr: "evt.name = 'RegSetValue' and registry.path not imatches 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\*'",
		},
		{
			name: "extracts file extension",
			expr: "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.extension = '.exe'",
			wantExtensions: map[string][]string{
				"=": {".exe"},
			},
		},
		{
			name: "extracts file base name",
			expr: "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.name icontains 'svchost'",
			wantBases: map[string][]string{
				"ICONTAINS": {"svchost"},
			},
		},
		{
			name: "extracts process executable",
			expr: "evt.name = 'OpenProcess' and evt.arg[exe] icontains 'lsass'",
			wantExecutables: map[string][]string{
				"ICONTAINS": {"lsass"},
			},
		},
	}

	c := newCompiler(new(ps.SnapshotterMock), newConfig(""))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ql.NewParser(tt.expr)
			n, err := p.ParseExpr()
			require.NoError(t, err)

			c.visitApproverPredicates(n)

			if tt.wantKeys != nil {
				assertMapEqual(t, "Keys", c.approvers.Keys, tt.wantKeys)
			}

			if tt.wantPaths != nil {
				assertMapEqual(t, "Paths", c.approvers.Paths, tt.wantPaths)
			}

			if tt.wantExtensions != nil {
				assertMapEqual(t, "Extensions", c.approvers.Extensions, tt.wantExtensions)
			}

			if tt.wantBases != nil {
				assertMapEqual(t, "Bases", c.approvers.Bases, tt.wantBases)
			}

			if tt.wantExecutables != nil {
				assertMapEqual(t, "Executables", c.approvers.Executables, tt.wantExecutables)
			}
		})
	}

	assert.Len(t, c.approvers.Paths, 1)
	assert.Len(t, c.approvers.Keys, 1)
	assert.Len(t, c.approvers.Extensions, 1)
	assert.Len(t, c.approvers.Bases, 1)
	assert.Len(t, c.approvers.Executables, 1)
}

func assertMapEqual(t *testing.T, name string, got, want map[string][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d keys, want %d keys. got=%v want=%v", name, len(got), len(want), got, want)
		return
	}
	for k, wantVals := range want {
		gotVals, ok := got[k]
		if !ok {
			t.Errorf("%s: missing key %q", name, k)
			continue
		}
		if len(gotVals) != len(wantVals) {
			t.Errorf("%s[%q]: got %v, want %v", name, k, gotVals, wantVals)
			continue
		}
		for i, v := range wantVals {
			if gotVals[i] != v {
				t.Errorf("%s[%q][%d]: got %q, want %q", name, k, i, gotVals[i], v)
			}
		}
	}
}
