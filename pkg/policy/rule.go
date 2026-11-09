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
	"fmt"
	"net"

	"github.com/rabbitstack/fibratus/pkg/policy/schemas"
	"gopkg.in/yaml.v3"
)

// RuleID represents the ID of a rule.
type RuleID string

// RuleDef is the definition of a detection rule.
type RuleDef struct {
	// ID is the unique rule identifier (UUID).
	ID RuleID `yaml:"id" json:"id"`

	// Name is the human-readable rule name.
	Name string `yaml:"name" json:"name"`

	// Description describes what the rule detects.
	Description string `yaml:"description" json:"description"`

	// Version is the semantic version of the rule.
	Version string `yaml:"version" json:"version"`

	// Condition is the rule expression. It is either a single
	// expression or a sequence.
	Condition string `yaml:"condition" json:"condition"`

	// Action lists the actions to execute when the rule matches.
	// An action runs only if it is populated in the rule YAML.
	Action []ActionDefinition `yaml:"action,omitempty" json:"action,omitempty"`

	// Output is the alert text template. It may refer to event
	// fields with the %field.name syntax.
	Output string `yaml:"output" json:"output"`

	// Severity is the alert severity: low, medium, high or critical.
	Severity string `yaml:"severity" json:"severity"`

	// Labels are arbitrary key/value pairs attached to the alert.
	Labels map[string]string `yaml:"labels" json:"labels"`

	// Tags are the labels used for rule classification, e.g. MITRE
	// technique names.
	Tags []string `yaml:"tags" json:"tags"`

	// References contains links with additional information.
	References []string `yaml:"references" json:"references"`

	// Notes contains free-form analyst notes.
	Notes string `yaml:"notes" json:"notes"`

	// MinEngineVersion is the minimum engine version that can run the rule.
	MinEngineVersion string `yaml:"min-engine-version" json:"min-engine-version"`

	// Enabled controls whether the rule is loaded. Rules are enabled
	// by default, so only an explicit false disables the rule.
	Enabled *bool `yaml:"enabled" json:"enabled"`

	// Authors lists the rule authors.
	Authors []string `yaml:"authors" json:"authors"`
}

// IsDisabled determines if this rule is disabled.
func (r *RuleDef) IsDisabled() bool { return r.Enabled != nil && !*r.Enabled }

// HasLabel determines if the rule has the given label.
func (r *RuleDef) HasLabel(l string) bool { return r.Labels[l] != "" }

// Validate checks the structural validity of the rule definition.
func (r *RuleDef) Validate() error {
	switch {
	case r.ID == "":
		return fmt.Errorf("rule %q is missing the id", r.Name)
	case r.Name == "":
		return fmt.Errorf("rule %s is missing the name", r.ID)
	case r.Condition == "":
		return fmt.Errorf("rule %q is missing the condition", r.Name)
	}
	for i, a := range r.Action {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("rule %q action #%d: %v", r.Name, i+1, err)
		}
	}
	return nil
}

// ruleDef has the same fields as RuleDef but none of its methods, so
// decoding into it doesn't call RuleDef.UnmarshalYAML again.
type ruleDef RuleDef

// UnmarshalYAML implements yaml.Unmarshaler. The node is validated against
// the rule JSON schema first, then decoded into the RuleDef and checked
// with Validate.
func (r *RuleDef) UnmarshalYAML(node *yaml.Node) error {
	var v any
	if err := node.Decode(&v); err != nil {
		return fmt.Errorf("line %d: invalid yaml: %v", node.Line, err)
	}
	if valid, errs := schemas.ValidateRuleSchema(v); !valid || len(errs) > 0 {
		return schemas.InvalidDefinitionError("rule", fmt.Sprintf("line %d", node.Line), v, errs)
	}
	return node.Decode((*ruleDef)(r))
}

// ActionDefinition describes a single action the rule triggers. Only
// the populated action fields are executed.
type ActionDefinition struct {
	// Kill terminates the processes that participated in the match.
	Kill *KillAction `yaml:"kill,omitempty" json:"kill,omitempty"`
	// Isolate isolates the host via firewall rules.
	Isolate *IsolateAction `yaml:"isolate,omitempty" json:"isolate,omitempty"`
}

// KillAction defines an action for killing the process
// indicated by the rule.
type KillAction struct{}

// IsolateAction defines an action for isolating the host
// via firewall rules.
type IsolateAction struct {
	// Whitelist contains IP addresses that should remain accessible.
	Whitelist []net.IP `yaml:"whitelist,omitempty" json:"whitelist,omitempty"`
}

// UnmarshalYAML decodes the action definition. It accepts the keyed form
//
//	action:
//	  - kill: {}
//	  - isolate:
//	      whitelist: [127.0.0.1]
//
// as well as the legacy form where the action is selected by the name key:
//
//	action:
//	  - name: isolate
//	    whitelist: [127.0.0.1]
func (a *ActionDefinition) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: action must be a mapping", n.Line)
	}

	var (
		name      string
		whitelist *yaml.Node
	)
	*a = ActionDefinition{}

	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "name":
			name = v.Value
		case "whitelist":
			whitelist = v
		case "kill":
			if a.Kill != nil {
				return fmt.Errorf("line %d: duplicate kill action", k.Line)
			}
			if err := checkEmptyAction(k, v); err != nil {
				return err
			}
			a.Kill = &KillAction{}
		case "isolate":
			if a.Isolate != nil {
				return fmt.Errorf("line %d: duplicate isolate action", k.Line)
			}
			a.Isolate = &IsolateAction{}
			if v.Kind == yaml.MappingNode {
				if err := v.Decode(a.Isolate); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("line %d: unknown action key %q", k.Line, k.Value)
		}
	}

	if name != "" {
		if a.Kill != nil || a.Isolate != nil {
			return fmt.Errorf("line %d: action mixes the name key with keyed actions", n.Line)
		}
		switch name {
		case "kill":
			a.Kill = &KillAction{}
			if whitelist != nil {
				return fmt.Errorf("line %d: kill action doesn't accept whitelist", whitelist.Line)
			}
		case "isolate":
			a.Isolate = &IsolateAction{}
			if whitelist != nil {
				ips, err := decodeIPs(whitelist)
				if err != nil {
					return err
				}
				a.Isolate.Whitelist = ips
			}
		default:
			return fmt.Errorf("line %d: unknown action %q", n.Line, name)
		}
	} else if whitelist != nil {
		return fmt.Errorf("line %d: whitelist is only valid for the isolate action", whitelist.Line)
	}

	return a.Validate()
}

func checkEmptyAction(k, v *yaml.Node) error {
	if v.Kind == yaml.MappingNode && len(v.Content) > 0 {
		return fmt.Errorf("line %d: %s action doesn't accept any parameters", k.Line, k.Value)
	}
	return nil
}

// UnmarshalYAML decodes IP addresses from strings.
func (a *IsolateAction) UnmarshalYAML(n *yaml.Node) error {
	var aux struct {
		Whitelist yaml.Node `yaml:"whitelist"`
	}
	if err := n.Decode(&aux); err != nil {
		return err
	}
	if aux.Whitelist.Kind == 0 {
		return nil
	}
	ips, err := decodeIPs(&aux.Whitelist)
	if err != nil {
		return err
	}
	a.Whitelist = ips
	return nil
}

// decodeIPs decodes the YAML sequence of IP address strings.
func decodeIPs(n *yaml.Node) ([]net.IP, error) {
	var vals []string
	if err := n.Decode(&vals); err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(vals))
	for _, s := range vals {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("line %d: %q is not a valid IP address", n.Line, s)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// Validate checks that exactly one action is populated.
func (a ActionDefinition) Validate() error {
	var n int
	if a.Kill != nil {
		n++
	}
	if a.Isolate != nil {
		n++
	}
	switch {
	case n == 0:
		return fmt.Errorf("action doesn't define any action")
	case n > 1:
		return fmt.Errorf("action must define a single action")
	}
	return nil
}
