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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("_fixtures/" + name)
	require.NoError(t, err)
	return b
}

func TestDecodeRule(t *testing.T) {
	r, err := DecodeRule("default.yml", readFixture(t, "rules/default.yml"))
	require.NoError(t, err)

	assert.Equal(t, "only network category", r.Name)
	assert.Equal(t, RuleID("313933e7-8eb9-45d9-81af-0305fee70e29"), r.ID)
	assert.Equal(t, "1.0.0", r.Version)
	require.NotNil(t, r.Enabled)
	assert.True(t, *r.Enabled)
	assert.Contains(t, r.Tags, "TE")
	assert.Equal(t, "evt.category = 'net'", r.Condition)
	assert.Equal(t, "this rule matches all network signals", r.Description)
	assert.Equal(t, "low", r.Severity)
	assert.Equal(t, "`%ps.exe` attempted to reach out to `%net.sip` IP address\n", r.Output)
	assert.Contains(t, r.References, "ref2")
	assert.NotEmpty(t, r.Notes)
	assert.Len(t, r.Authors, 2)
	assert.Equal(t, "2.0.0", r.MinEngineVersion)

	require.Len(t, r.Action, 2)
	assert.NotNil(t, r.Action[0].Kill)
	require.NotNil(t, r.Action[1].Isolate)
	require.Len(t, r.Action[1].Isolate.Whitelist, 2)
	assert.Contains(t, r.Action[1].Isolate.Whitelist[0].String(), "127.0.0.1")
}

func TestDecodeRuleDefaults(t *testing.T) {
	r, err := DecodeRule("default1.yml", readFixture(t, "rules/default1.yml"))
	require.NoError(t, err)

	assert.False(t, r.IsDisabled())
	assert.Equal(t, "suspicious network ACTIVITY", r.Name)
	assert.Equal(t, "evt.category = 'net' and ps.name in ('at.exe', 'java.exe')", r.Condition)
	assert.Empty(t, r.Action)
}

func TestDecodeRuleWithTemplate(t *testing.T) {
	r, err := DecodeRule("default-with-template.yml", readFixture(t, "rules/default-with-template.yml"))
	require.NoError(t, err)
	assert.Equal(t, "ALL NETWORK EVENTS\n", r.Output)
}

func TestDecodeRuleKeyedActions(t *testing.T) {
	r, err := DecodeRule("keyed.yml", []byte(`
name: keyed actions
id: 8b3cb3a0-1e6a-4c55-8d9b-8f5d6b1b8a11
version: 1.0.0
condition: evt.name = 'CreateProcess'
min-engine-version: 2.0.0
action:
  - kill: {}
  - isolate:
      whitelist:
        - 10.0.0.1
`))
	require.NoError(t, err)
	require.Len(t, r.Action, 2)
	assert.NotNil(t, r.Action[0].Kill)
	require.NotNil(t, r.Action[1].Isolate)
	assert.Len(t, r.Action[1].Isolate.Whitelist, 1)
}

func TestDecodeRuleErrors(t *testing.T) {
	const valid = `
name: rule name
id: 8b3cb3a0-1e6a-4c55-8d9b-8f5d6b1b8a11
version: 1.0.0
condition: evt.name = 'CreateProcess'
min-engine-version: 2.0.0
`
	var tests = []struct {
		name string
		yaml string
		err  string
	}{
		{"not yaml", "name: [unclosed", "invalid yaml"},
		{"missing id", "name: rule name\nversion: 1.0.0\ncondition: evt.name = 'x'\nmin-engine-version: 2.0.0\n", "invalid rule definition"},
		{"baseline is valid", valid, ""},
		{"bad severity", valid + "severity: urgent\n", "invalid rule definition"},
		{"unknown property", valid + "foo: bar\n", "invalid rule definition"},
		{"bad version", "name: rule name\nid: 8b3cb3a0-1e6a-4c55-8d9b-8f5d6b1b8a11\nversion: one\ncondition: evt.name = 'x'\nmin-engine-version: 2.0.0\n", "invalid rule definition"},
		{"unknown action", valid + "action:\n  - name: reboot\n", "invalid rule definition"},
		{"whitelist for kill", valid + "action:\n  - name: kill\n    whitelist: [1.1.1.1]\n", "invalid rule definition"},
		{"invalid whitelist ip", valid + "action:\n  - name: isolate\n    whitelist: [nope]\n", "invalid rule definition"},
		{"empty whitelist", valid + "action:\n  - name: isolate\n    whitelist: []\n", "invalid rule definition"},
		{"template syntax", valid + "output: \"{{ nope\"\n", "syntax error"},
		{"template missing function", valid + "output: \"{{ nofunc 1 }}\"\n", "syntax error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeRule("rule.yml", []byte(tt.yaml))
			if tt.err == "" {
				// the "valid" baseline has to decode properly
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestDecodeMacros(t *testing.T) {
	macros, err := DecodeMacros("macros.yml", []byte(`
- macro: spawn_process
  expr: evt.name = 'CreateProcess'
  description: Identifies the execution of a new process

- macro: shells
  list:
    - cmd.exe
    - powershell.exe
`))
	require.NoError(t, err)
	require.Len(t, macros, 2)

	assert.Equal(t, "spawn_process", macros[0].ID)
	assert.Equal(t, "evt.name = 'CreateProcess'", macros[0].Expression)
	assert.Equal(t, "Identifies the execution of a new process", macros[0].Description)
	assert.False(t, macros[0].IsList())

	assert.Equal(t, "shells", macros[1].ID)
	assert.Equal(t, []string{"cmd.exe", "powershell.exe"}, macros[1].Values)
	assert.True(t, macros[1].IsList())
}

func TestDecodeMacrosErrors(t *testing.T) {
	var tests = []struct {
		name string
		yaml string
		err  string
	}{
		{"not yaml", "- macro: [unclosed", "invalid macro yaml"},
		{"not a list", "macro: foo\nexpr: evt.name = 'x'\n", "invalid macro definition"},
		{"missing expr and list", "- macro: foo\n", "invalid macro definition"},
		{"both expr and list", "- macro: foo\n  expr: evt.name = 'x'\n  list: [a]\n", "invalid macro definition"},
		{"bad id", "- macro: 'foo bar'\n  expr: evt.name = 'x'\n", "invalid macro definition"},
		{"unknown property", "- macro: foo\n  expr: evt.name = 'x'\n  bar: baz\n", "invalid macro definition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMacros("macros.yml", []byte(tt.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestToStringKeys(t *testing.T) {
	out, err := toStringKeys(map[any]any{"a": []any{map[any]any{"b": 1}}}, "")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": []any{map[string]any{"b": 1}}}, out)

	_, err = toStringKeys(map[any]any{1: "x"}, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-string key")
}
