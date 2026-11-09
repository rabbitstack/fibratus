/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesConfigInitFromViper(t *testing.T) {
	var tests = []struct {
		name     string
		settings map[string]any
		expected RulesConfig
	}{
		{
			"defaults are the zero value",
			map[string]any{},
			RulesConfig{},
		},
		{
			"enabled only",
			map[string]any{rulesEnabled: true},
			RulesConfig{Enabled: true},
		},
		{
			"rule and macro paths",
			map[string]any{
				rulesEnabled: true,
				rulePaths:    []string{`C:\Rules\*.yml`, `D:\Rules\*.yaml`},
				macroPaths:   []string{`C:\Rules\Macros\*.yml`},
			},
			RulesConfig{
				Enabled:    true,
				RulePaths:  []string{`C:\Rules\*.yml`, `D:\Rules\*.yaml`},
				MacroPaths: []string{`C:\Rules\Macros\*.yml`},
			},
		},
		{
			"match all strategy",
			map[string]any{rulesEnabled: true, matchAll: true},
			RulesConfig{Enabled: true, MatchAll: true},
		},
		{
			"disabled engine keeps paths",
			map[string]any{rulesEnabled: false, rulePaths: []string{`C:\Rules\*`}},
			RulesConfig{RulePaths: []string{`C:\Rules\*`}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			for k, val := range tt.settings {
				v.Set(k, val)
			}
			var rc RulesConfig
			rc.initFromViper(v)
			assert.Equal(t, tt.expected.Enabled, rc.Enabled)
			assert.Equal(t, tt.expected.MatchAll, rc.MatchAll)
			assert.ElementsMatch(t, tt.expected.RulePaths, rc.RulePaths)
			assert.ElementsMatch(t, tt.expected.MacroPaths, rc.MacroPaths)
		})
	}
}

func TestRulesConfigKeys(t *testing.T) {
	// the viper keys are part of the public config schema, so make sure
	// that nobody changes them by accident
	assert.Equal(t, "rules.enabled", rulesEnabled)
	assert.Equal(t, "rules.rule-paths", rulePaths)
	assert.Equal(t, "rules.macro-paths", macroPaths)
	assert.Equal(t, "rules.match-all", matchAll)
}

func TestRulesConfigFromYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(stringsReader(`
rules:
  enabled: true
  match-all: true
  rule-paths:
    - C:\Rules\*.yml
  macro-paths:
    - C:\Rules\Macros\*.yml
`)))

	var rc RulesConfig
	rc.initFromViper(v)

	assert.True(t, rc.Enabled)
	assert.True(t, rc.MatchAll)
	require.Len(t, rc.RulePaths, 1)
	assert.Equal(t, `C:\Rules\*.yml`, rc.RulePaths[0])
	require.Len(t, rc.MacroPaths, 1)
	assert.Equal(t, `C:\Rules\Macros\*.yml`, rc.MacroPaths[0])
}

func TestRulesConfigSchema(t *testing.T) {
	valid := map[string]any{
		"rules": map[string]any{
			"enabled":     true,
			"match-all":   false,
			"rule-paths":  []any{`C:\Rules\*.yml`},
			"macro-paths": []any{`C:\Rules\Macros\*.yml`},
		},
	}
	ok, errs := validate(configSchema, valid)
	assert.True(t, ok, "%v", errs)

	// the old filters section is no longer part of the schema
	old := map[string]any{
		"filters": map[string]any{
			"rules": map[string]any{"enabled": true},
		},
	}
	ok, _ = validate(configSchema, old)
	assert.False(t, ok)

	// unknown keys under rules are rejected
	unknown := map[string]any{
		"rules": map[string]any{"from-urls": []any{"http://localhost/rule.yml"}},
	}
	ok, _ = validate(configSchema, unknown)
	assert.False(t, ok)
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
