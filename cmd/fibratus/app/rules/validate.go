/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"github.com/enescakir/emoji"
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"path/filepath"
	"strings"
)

func validateRules() error {
	if err := bootstrap.InitConfigAndLogger(cfg); err != nil {
		return err
	}

	isValidExt := func(path string) bool {
		return filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml"
	}
	// load macros and rules
	for _, m := range cfg.Filters.Macros.FromPaths {
		paths, err := filepath.Glob(m)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			emo("%v Loading macros from %s\n", emoji.Hook, path)
		}
	}
	if err := cfg.Filters.LoadMacros(); err != nil {
		return fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}

	for _, r := range cfg.Filters.Rules.FromPaths {
		paths, err := filepath.Glob(r)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			emo("%v Loading rules from %s\n", emoji.Package, path)
		}
	}
	if err := cfg.Filters.LoadGroups(); err != nil {
		return fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}
	if len(cfg.GetRuleGroups()) == 0 {
		return fmt.Errorf("%v no rules found in %s", emoji.DisappointedFace, strings.Join(cfg.Filters.Rules.FromPaths, ","))
	}

	warnings := make([]string, 0)
	// validate rule for every group
	for _, group := range cfg.GetRuleGroups() {
		for _, rule := range group.Rules {
			f := filter.New(rule.Condition, cfg)
			err := f.Compile()
			if err != nil {
				return fmt.Errorf("%v %v", emoji.DisappointedFace, filter.ErrInvalidFilter(rule.Name, group.Name, err))
			}
			for _, fld := range f.GetFields() {
				if isDeprecated, dep := fields.IsDeprecated(fld); isDeprecated {
					warnings = append(warnings,
						fmt.Sprintf("%s field deprecated in favor of %v in rule %s", fld.String(), dep.Fields, rule.Name))
				}
			}
		}
	}
	if len(warnings) > 0 {
		for _, warn := range warnings {
			emo("%v %s\n", emoji.Warning, warn)
		}
		fmt.Printf("%d warning(s)\n", len(warnings))
	}

	emo("%v Validation successful. Ready to go!", emoji.Rocket)
	return nil
}
