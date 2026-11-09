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
	"github.com/spf13/viper"
)

const (
	rulesEnabled = "rules.enabled"
	rulePaths    = "rules.rule-paths"
	macroPaths   = "rules.macro-paths"
	matchAll     = "rules.match-all"
)

// RulesConfig describes rule engine configuration.
type RulesConfig struct {
	// Enabled indicates if the rule engine is enabled.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// RulePaths rule paths when they are loaded from static FS paths.
	RulePaths []string `json:"rule-paths" yaml:"rule-paths"`
	// MacroPaths macro paths when they are loaded from static FS paths.
	MacroPaths []string `json:"macro-paths" yaml:"macro-paths"`
	// MatchAll indicates if the match all strategy is enabled for the rule engine.
	// If the match all strategy is enabled, a single event can trigger multiple rules.
	MatchAll bool `json:"match-all" yaml:"match-all"`
}

func (r *RulesConfig) initFromViper(v *viper.Viper) {
	r.Enabled = v.GetBool(rulesEnabled)
	r.RulePaths = v.GetStringSlice(rulePaths)
	r.MacroPaths = v.GetStringSlice(macroPaths)
	r.MatchAll = v.GetBool(matchAll)
}
