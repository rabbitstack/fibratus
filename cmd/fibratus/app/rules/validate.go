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
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
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

	rs, err := loadRuleSet(true)
	if err != nil {
		return err
	}

	for _, p := range rs.GetPolicies() {
		emo("%v Loaded policy %s (%d rules, %d macros)\n", emoji.Package, p.Source, len(p.Rules), len(p.Macros))
	}

	warnings := make([]warning, 0)

	// the rule set compiles all rules, so every syntax error is already
	// reported. The rules left out of the rule set are reported as errors
	for _, d := range rs.Report().Discarded {
		return fmt.Errorf("%v rule %s in %s: %s", emoji.DisappointedFace, d.Name, d.Source, d.Reason)
	}

	for _, rule := range rs.GetRules() {
		w := warning{rule: rule.Name}
		for _, fld := range rule.Evaluator().GetFields() {
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
