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
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// FiltersConfig contains references to rule and macro paths
// and controls the behaviour of the rule engine.
type FiltersConfig struct {
	Rules  Rules  `json:"rules" yaml:"rules"`
	Macros Macros `json:"macros" yaml:"macros"`
	// MatchAll indicates if the match all strategy is enabled for the rule engine.
	// If the match all strategy is enabled, a single event can trigger multiple rules.
	MatchAll bool `json:"match-all" yaml:"match-all"`
}

// Rules contains attributes that describe the location of
// rule resources and controls whether the rule engine is
// enabled.
type Rules struct {
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	FromPaths []string `json:"from-paths" yaml:"from-paths"`
}

// Macros contains attributes that describe the location of
// macro resources.
type Macros struct {
	FromPaths []string `json:"from-paths" yaml:"from-paths"`
}

const (
	rulesEnabled    = "filters.rules.enabled"
	rulesFromPaths  = "filters.rules.from-paths"
	macrosFromPaths = "filters.macros.from-paths"
	matchAll        = "filters.match-all"
)

func (f *FiltersConfig) initFromViper(v *viper.Viper) {
	f.Rules.Enabled = v.GetBool(rulesEnabled)
	f.Rules.FromPaths = v.GetStringSlice(rulesFromPaths)
	f.Macros.FromPaths = v.GetStringSlice(macrosFromPaths)
	f.MatchAll = v.GetBool(matchAll)
}

func ValidateRuleSchema(path string, out any) error {
	s, errs, err := validateSchema(rulesSchema, out)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid rule definition: \n\n"+
			"%v in %s: %v", s, path, multierror.Wrap(errs...))
	}
	return nil
}

func ValidateMacroSchema(path string, out any) error {
	s, errs, err := validateSchema(macrosSchema, out)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid macro definition: \n\n"+
			"%v in %s: %v", s, path, multierror.Wrap(errs...))
	}
	return nil
}

func validateSchema(schema string, out any) (string, []error, error) {
	valid, errs := validate(schema, out)
	if !valid || len(errs) > 0 {
		raw := out
		b, err := yaml.Marshal(&raw)
		if err != nil {
			return "", errs, err
		}
		return string(b), errs, nil
	}
	return "", nil, nil
}
