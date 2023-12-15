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

	for _, m := range cfg.Filters.Macros.FromPaths {
		paths, err := filepath.Glob(m)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			emo("%v Loading macros from %s\n", emoji.Magnet, path)
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

	for _, group := range cfg.GetRuleGroups() {
		for _, rule := range group.Rules {
			f := filter.New(rule.Condition, cfg)
			err := f.Compile()
			if err != nil {
				return fmt.Errorf("%v %v", emoji.DisappointedFace, filter.ErrInvalidFilter(rule.Name, group.Name, err))
			}
			for _, field := range f.GetFields() {
				deprecated, d := fields.IsDeprecated(field)
				if deprecated {
					emo("%v Deprecation: %s rule uses "+
						"the [%s] field which was deprecated starting "+
						"from version %s. "+
						"Please consider migrating to %s field(s) "+
						"because [%s] will be removed in future versions\n",
						emoji.Warning, rule.Name, field, d.Since, d.Fields, field)
				}
			}
		}
	}
	emo("%v Detection rules OK. Ready to go!", emoji.Rocket)
	return nil
}
