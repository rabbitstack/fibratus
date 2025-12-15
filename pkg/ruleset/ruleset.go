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

import (
	"fmt"
	"slices"
	"strings"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/pkg/event"
)

type RuleSet struct {
	Macros map[string]*Macro
	Rules  []*Rule
}

type Subscriber interface {
	Compile(*RuleSet) (*CompileResult, error)
}

func New() *RuleSet {
	return &RuleSet{
		Macros: make(map[string]*Macro),
		Rules:  make([]*Rule, 0),
	}
}

func (rs *RuleSet) AddRule(r *Rule) {
	rs.Rules = append(rs.Rules, r)
}

func (rs *RuleSet) AddMacro(m *Macro) {
	rs.Macros[m.ID] = m
}

func (rs *RuleSet) AddMacros(macros ...Macro) {
	for _, m := range macros {
		rs.AddMacro(&m)
	}
}

func (rs *RuleSet) HasMacros() bool { return len(rs.Macros) > 0 }

func (rs *RuleSet) GetMacro(id string) *Macro { return rs.Macros[id] }

func (rs *RuleSet) IsMacroList(id string) bool {
	macro, ok := rs.Macros[id]
	if !ok {
		return false
	}
	return macro.List != nil
}

// FromProto converts the ruleset from the protobuf structure.
func (rs *RuleSet) FromProto(ruleset *rulesapi.RuleSet) {
	rs.Rules = make([]*Rule, 0, len(ruleset.Rules))
	rs.Macros = make(map[string]*Macro, len(ruleset.Macros))

	for _, m := range ruleset.Macros {
		macro := &Macro{
			ID: m.Id,
		}
		if m.Description != nil {
			macro.Description = *m.Description
		}
		if len(m.List) > 0 {
			macro.List = m.List
		} else {
			macro.Expr = m.Expr
		}
		rs.AddMacro(macro)
	}
	for _, r := range ruleset.Rules {
		var typ RuleType
		switch r.Type {
		case rulesapi.Type_TYPE_BEHAVIOUR:
			typ = BehaviourRule
		case rulesapi.Type_TYPE_YARA:
			typ = YaraRule
		}
		rule := &Rule{
			ID:               r.Id,
			Type:             typ,
			Name:             r.Name,
			Condition:        r.Condition,
			Version:          r.Version,
			MinEngineVersion: r.MinEngineVersion,
			Enabled:          &r.Enabled,
		}
		rs.AddRule(rule)
	}
}

// ToProto converts the ruleset to protobuf structure.
func (rs *RuleSet) ToProto() *rulesapi.RuleSet {
	rules := make([]*rulesapi.Rule, 0, len(rs.Rules))
	macros := make([]*rulesapi.Macro, 0, len(rs.Macros))

	for _, m := range rs.Macros {
		macro := &rulesapi.Macro{
			Id:          m.ID,
			Description: &m.Description,
		}
		if len(m.List) > 0 {
			macro.List = m.List
		} else {
			macro.Expr = m.Expr
		}
		macros = append(macros, macro)
	}

	for _, r := range rs.Rules {
		rule := &rulesapi.Rule{
			Id:               r.ID,
			Type:             rulesapi.Type_TYPE_BEHAVIOUR,
			Name:             r.Name,
			Condition:        r.Condition,
			Version:          r.Version,
			MinEngineVersion: r.MinEngineVersion,
		}
		if r.Enabled != nil && !*r.Enabled {
			rule.Enabled = false
		} else {
			rule.Enabled = true
		}
		rules = append(rules, rule)
	}

	return &rulesapi.RuleSet{
		Macros: macros,
		Rules:  rules,
	}
}

// IsEmpty returns true if the ruleset doesn't contain any rules.
func (rs *RuleSet) IsEmpty() bool {
	return len(rs.Rules) == 0
}

// CompileResult contains the stats of the
// compiled ruleset, like which event types or
// categories are used. This information permits
// enabling/disabling event providers/types
// dynamically.
type CompileResult struct {
	HasProcEvents       bool
	HasThreadEvents     bool
	HasImageEvents      bool
	HasFileEvents       bool
	HasNetworkEvents    bool
	HasRegistryEvents   bool
	HasHandleEvents     bool
	HasMemEvents        bool
	HasVAMapEvents      bool
	HasDNSEvents        bool
	HasAuditAPIEvents   bool
	HasThreadpoolEvents bool
	UsedEvents          []event.Type
	NumberRules         int
}

func (r CompileResult) ContainsEvent(typ event.Type) bool {
	return slices.Contains(r.UsedEvents, typ)
}

func (r CompileResult) String() string {
	m := map[string]bool{}
	events := make([]string, 0)
	for _, typ := range r.UsedEvents {
		if m[typ.String()] {
			continue
		}
		events = append(events, typ.String())
		m[typ.String()] = true
	}
	slices.Sort(events)
	return fmt.Sprintf(`
		HasProcEvents: %t
		HasThreadEvents: %t
		HasImageEvents: %t
		HasFileEvents: %t
		HasRegistryEvents: %t
		HasNetworkEvents: %t
		HasHandleEvents: %t
		HasMemEvents: %t
		HasVAMapEvents: %t
		HasAuditAPIEvents: %t
		HasDNSEvents: %t
		HasThreadpoolEvents: %t
		Events: %s`,
		r.HasProcEvents,
		r.HasThreadEvents,
		r.HasImageEvents,
		r.HasFileEvents,
		r.HasRegistryEvents,
		r.HasNetworkEvents,
		r.HasHandleEvents,
		r.HasMemEvents,
		r.HasVAMapEvents,
		r.HasAuditAPIEvents,
		r.HasDNSEvents,
		r.HasThreadpoolEvents,
		strings.Join(events, ", "),
	)
}
