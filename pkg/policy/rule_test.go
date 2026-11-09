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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestActionDefinitionUnmarshal(t *testing.T) {
	var tests = []struct {
		name     string
		yaml     string
		validate func(*testing.T, []ActionDefinition)
		err      string
	}{
		{
			"legacy kill",
			"- name: kill",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				assert.NotNil(t, a[0].Kill)
				assert.Nil(t, a[0].Isolate)
			},
			"",
		},
		{
			"legacy isolate with whitelist",
			"- name: isolate\n  whitelist:\n    - 127.0.0.1\n    - 8.8.8.8",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				require.NotNil(t, a[0].Isolate)
				assert.Nil(t, a[0].Kill)
				require.Len(t, a[0].Isolate.Whitelist, 2)
				assert.True(t, a[0].Isolate.Whitelist[0].Equal(net.ParseIP("127.0.0.1")))
				assert.True(t, a[0].Isolate.Whitelist[1].Equal(net.ParseIP("8.8.8.8")))
			},
			"",
		},
		{
			"legacy isolate without whitelist",
			"- name: isolate",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				require.NotNil(t, a[0].Isolate)
				assert.Empty(t, a[0].Isolate.Whitelist)
			},
			"",
		},
		{
			"keyed kill with empty mapping",
			"- kill: {}",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				assert.NotNil(t, a[0].Kill)
			},
			"",
		},
		{
			"keyed kill with null value",
			"- kill:",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				assert.NotNil(t, a[0].Kill)
			},
			"",
		},
		{
			"keyed isolate with whitelist",
			"- isolate:\n    whitelist: [10.0.0.1]",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				require.NotNil(t, a[0].Isolate)
				require.Len(t, a[0].Isolate.Whitelist, 1)
				assert.True(t, a[0].Isolate.Whitelist[0].Equal(net.ParseIP("10.0.0.1")))
			},
			"",
		},
		{
			"keyed isolate with null value",
			"- isolate:",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 1)
				require.NotNil(t, a[0].Isolate)
			},
			"",
		},
		{
			"multiple actions preserve order",
			"- kill: {}\n- name: isolate",
			func(t *testing.T, a []ActionDefinition) {
				require.Len(t, a, 2)
				assert.NotNil(t, a[0].Kill)
				assert.NotNil(t, a[1].Isolate)
			},
			"",
		},
		{"unknown legacy action", "- name: reboot", nil, `unknown action "reboot"`},
		{"unknown key", "- reboot: {}", nil, `unknown action key "reboot"`},
		{"kill with parameters", "- kill:\n    signal: 9", nil, "doesn't accept any parameters"},
		{"kill with legacy whitelist", "- name: kill\n  whitelist: [1.1.1.1]", nil, "kill action doesn't accept whitelist"},
		{"mixed name and keyed", "- name: kill\n  isolate: {}", nil, "mixes the name key"},
		{"two keyed actions in one item", "- kill: {}\n  isolate: {}", nil, "single action"},
		{"whitelist without name", "- whitelist: [1.1.1.1]", nil, "only valid for the isolate action"},
		{"invalid ip", "- name: isolate\n  whitelist: [not-an-ip]", nil, "not a valid IP address"},
		{"action not a mapping", "- kill", nil, "action must be a mapping"},
		{"empty item", "- {}", nil, "doesn't define any action"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actions []ActionDefinition
			err := yaml.Unmarshal([]byte(tt.yaml), &actions)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
				return
			}
			require.NoError(t, err)
			tt.validate(t, actions)
		})
	}
}

func TestRuleDefHelpers(t *testing.T) {
	enabled, disabled := true, false

	assert.False(t, (&RuleDef{}).IsDisabled())
	assert.False(t, (&RuleDef{Enabled: &enabled}).IsDisabled())
	assert.True(t, (&RuleDef{Enabled: &disabled}).IsDisabled())

	r := &RuleDef{Labels: map[string]string{"tactic": "TA0006", "empty": ""}}
	assert.True(t, r.HasLabel("tactic"))
	assert.False(t, r.HasLabel("empty"))
	assert.False(t, r.HasLabel("missing"))
}

func TestRuleDefValidate(t *testing.T) {
	var tests = []struct {
		name string
		rule RuleDef
		err  string
	}{
		{"valid", RuleDef{ID: "1", Name: "rule", Condition: "evt.name = 'CreateFile'"}, ""},
		{"missing id", RuleDef{Name: "rule", Condition: "evt.name = 'CreateFile'"}, "missing the id"},
		{"missing name", RuleDef{ID: "1", Condition: "evt.name = 'CreateFile'"}, "missing the name"},
		{"missing condition", RuleDef{ID: "1", Name: "rule"}, "missing the condition"},
		{
			"invalid action",
			RuleDef{ID: "1", Name: "rule", Condition: "x", Action: []ActionDefinition{{}}},
			"action #1",
		},
		{
			"valid action",
			RuleDef{ID: "1", Name: "rule", Condition: "x", Action: []ActionDefinition{{Kill: &KillAction{}}}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if tt.err == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestMacroDefValidate(t *testing.T) {
	var tests = []struct {
		name  string
		macro MacroDef
		err   string
	}{
		{"expression", MacroDef{ID: "spawn_process", Expression: "evt.name = 'CreateProcess'"}, ""},
		{"list", MacroDef{ID: "shells", Values: []string{"cmd.exe"}}, ""},
		{"empty list is a list", MacroDef{ID: "shells", Values: []string{}}, ""},
		{"missing id", MacroDef{Expression: "x"}, "missing the identifier"},
		{"invalid id", MacroDef{ID: "bad id", Expression: "x"}, "not a valid macro identifier"},
		{"both", MacroDef{ID: "m", Expression: "x", Values: []string{"a"}}, "both expression and list"},
		{"neither", MacroDef{ID: "m"}, "either expression or list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.macro.Validate()
			if tt.err == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}

	assert.True(t, (&MacroDef{ID: "m", Values: []string{"a"}}).IsList())
	assert.False(t, (&MacroDef{ID: "m", Expression: "x"}).IsList())
}

func TestPolicyType(t *testing.T) {
	assert.True(t, (&Policy{Type: BehaviourPolicyType}).IsBehaviour())
	assert.False(t, (&Policy{Type: BehaviourPolicyType}).IsSignature())
	assert.True(t, (&Policy{Type: SignaturePolicyType}).IsSignature())
}
