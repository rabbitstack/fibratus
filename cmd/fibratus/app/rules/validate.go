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
	"github.com/rabbitstack/fibratus/pkg/rules"
	"path/filepath"
	"strings"
)

type warning struct {
	rule     string
	messages []string
}

func (w *warning) addMessage(msg string) {
	if w.messages == nil {
		w.messages = make([]string, 0)
	}
	w.messages = append(w.messages, msg)
}

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
			emo("%v Loading rule %s\n", emoji.Package, path)
		}
	}
	if err := cfg.Filters.LoadFilters(); err != nil {
		return fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}
	if len(cfg.GetFilters()) == 0 {
		return fmt.Errorf("%v no rules found in %s", emoji.DisappointedFace, strings.Join(cfg.Filters.Rules.FromPaths, ","))
	}

	warnings := make([]warning, 0)

	// validate rules
	for _, rule := range cfg.GetFilters() {
		f := filter.New(rule.Condition, cfg)
		err := f.Compile()
		if err != nil {
			return fmt.Errorf("%v %v", emoji.DisappointedFace, rules.ErrInvalidFilter(rule.Name, err))
		}

		w := warning{rule: rule.Name}
		for _, fld := range f.GetFields() {
			if isDeprecated, dep := fields.IsDeprecated(fld.Name); isDeprecated {
				w.addMessage(fmt.Sprintf("%s field deprecated in favor of %v", fld.Name.String(), dep.Fields))
			}
		}

		if !rule.HasLabel("tactic.id") {
			w.addMessage("tactic.id label is missing")
		}
		if !rule.HasLabel("tactic.name") {
			w.addMessage("tactic.name label is missing")
		}
		if !rule.HasLabel("tactic.ref") {
			w.addMessage("tactic.ref label is missing")
		}
		if !rule.HasLabel("technique.id") {
			w.addMessage("technique.id label is missing")
		}
		if !rule.HasLabel("technique.name") {
			w.addMessage("technique.name label is missing")
		}
		if !rule.HasLabel("technique.ref") {
			w.addMessage("technique.ref label is missing")
		}

		if len(w.messages) > 0 {
			warnings = append(warnings, w)
		}
	}

	for _, warn := range warnings {
		emo("%v %d warning(s) in rule %s:\n", emoji.Warning, len(warn.messages), warn.rule)
		for _, msg := range warn.messages {
			fmt.Printf("  %v %s\n", emoji.Warning, msg)
		}
	}

	emo("%v Validation successful. Ready to go!", emoji.Rocket)
	return nil
}
