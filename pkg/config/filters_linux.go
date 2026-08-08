//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

import "github.com/spf13/viper"

const (
	rulesEnabled    = "filters.rules.enabled"
	rulesFromPaths  = "filters.rules.from-paths"
	rulesFromURLs   = "filters.rules.from-urls"
	macrosFromPaths = "filters.macros.from-paths"
	matchAll        = "filters.match-all"
)

type FilterConfig struct{}

type Filters struct {
	Rules struct {
		Enabled   bool
		FromPaths []string
		FromURLs  []string
	}
	MatchAll bool
	filters  []*FilterConfig
}

func (f *Filters) initFromViper(v *viper.Viper) {
	f.Rules.Enabled = v.GetBool(rulesEnabled)
	f.Rules.FromPaths = v.GetStringSlice(rulesFromPaths)
	f.Rules.FromURLs = v.GetStringSlice(rulesFromURLs)
	f.MatchAll = v.GetBool(matchAll)
}
