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

package ruleset

import "github.com/rabbitstack/fibratus/pkg/config"

type RuleType uint8

const (
	BehaviourRule RuleType = 1 + iota
	YaraRule
)

// Rule describes all the necessary attributes of the rule.
type Rule struct {
	ID               string            `json:"id" yaml:"id"`
	Type             RuleType          `json:"-" yaml:"-"`
	Name             string            `json:"name" yaml:"name"`
	Description      string            `json:"description" yaml:"description"`
	Version          string            `json:"version" yaml:"version"`
	Condition        string            `json:"condition" yaml:"condition"`
	Action           []RuleAction      `json:"action" yaml:"action"`
	Output           string            `json:"output" yaml:"output"`
	Severity         string            `json:"severity" yaml:"severity"`
	Labels           map[string]string `json:"labels" yaml:"labels"`
	Tags             []string          `json:"tags" yaml:"tags"`
	References       []string          `json:"references" yaml:"references"`
	Notes            string            `json:"notes" yaml:"notes"`
	MinEngineVersion string            `json:"min-engine-version" yaml:"min-engine-version"`
	Enabled          *bool             `json:"enabled" yaml:"enabled"`
	Authors          []string          `json:"authors" yaml:"authors"`
	Patterns         string            `json:"-" yaml:"-"`
	Imports          []string          `json:"-" yaml:"-"`
}

// IsDisabled determines if this rule is disabled.
func (r Rule) IsDisabled() bool { return r.Enabled != nil && !*r.Enabled }

// IsBehaviour determines if this is behaviour rule.
func (r Rule) IsBehaviour() bool { return r.Type == BehaviourRule }

// HasLabel determines if the rule has the given label.
func (f Rule) HasLabel(l string) bool { return f.Labels[l] != "" }

// DecodeActions converts the raw map to typed action structures.
func (r Rule) DecodeActions() ([]any, error) {
	actions := make([]any, 0, len(r.Action))

	decode := func(m map[string]any, o any) error {
		err := config.Decode(m, &o)
		if err != nil {
			return err
		}
		actions = append(actions, o)
		return nil
	}

	for _, act := range r.Action {
		m, ok := act.(map[string]any)
		if !ok {
			continue
		}
		switch m["name"] {
		case "kill":
			var kill KillAction
			if err := decode(m, kill); err != nil {
				return nil, err
			}
		case "isolate":
			var isolate IsolateAction
			if err := decode(m, isolate); err != nil {
				return nil, err
			}
		}
	}

	return actions, nil
}
