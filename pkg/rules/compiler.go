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

package rules

import (
	"expvar"
	"fmt"
	"slices"
	"strings"

	semver "github.com/hashicorp/go-version"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	log "github.com/sirupsen/logrus"
)

var (
	// filtersCount computes the total number of filters in the ruleset
	filtersCount = expvar.NewInt("filter.filters.count")

	ErrInvalidFilter = func(rule string, err error) error {
		return fmt.Errorf("syntax error in rule %q: \n%v", rule, err)
	}
	ErrIncompatibleFilter = func(rule, v string) error {
		return fmt.Errorf("rule %q needs engine version [%s] but current version is [%s]", rule, v, version.Get())
	}
	ErrMalformedMinEngineVer = func(rule, v string, err error) error {
		return fmt.Errorf("rule %q has a malformed minimum engine version: %s: %v", rule, v, err)
	}
	ErrUnknownEventName = func(rule, name string) error {
		return fmt.Errorf("rule %s references an invalid event name %q in the evt.name field", rule, name)
	}
	ErrUnknownCategoryName = func(rule, name string) error {
		return fmt.Errorf("rule %s references an invalid event category %q in the evt.category field", rule, name)
	}
)

type compiler struct {
	psnap     ps.Snapshotter
	config    *config.Config
	approvers config.Approvers
}

func newCompiler(psnap ps.Snapshotter, cfg *config.Config) *compiler {
	return &compiler{psnap: psnap, config: cfg, approvers: config.Approvers{
		Keys:        make(map[string][]string),
		Paths:       make(map[string][]string),
		Extensions:  make(map[string][]string),
		Bases:       make(map[string][]string),
		Executables: make(map[string][]string),
	}}
}

func (c *compiler) compile() (map[*config.FilterConfig]filter.Filter, *config.RulesCompileResult, error) {
	if err := c.config.Filters.LoadMacros(); err != nil {
		return nil, nil, err
	}
	if err := c.config.Filters.LoadFilters(); err != nil {
		return nil, nil, err
	}

	filters := make(map[*config.FilterConfig]filter.Filter)

	for _, f := range c.config.GetFilters() {
		if f.IsDisabled() {
			log.Warnf("[%s] rule is disabled", f.Name)
			continue
		}

		filtersCount.Add(1)

		// compile the filter
		fltr := filter.New(f.Condition, c.config, filter.WithPSnapshotter(c.psnap))
		err := fltr.Compile()
		if err != nil {
			return nil, nil, ErrInvalidFilter(f.Name, err)
		}
		// check version requirements
		if !version.IsDev() {
			minEngineVer, err := semver.NewSemver(f.MinEngineVersion)
			if err != nil {
				return nil, nil, ErrMalformedMinEngineVer(f.Name, f.MinEngineVersion, err)
			}
			if minEngineVer.GreaterThan(version.Sem()) {
				return nil, nil, ErrIncompatibleFilter(f.Name, f.MinEngineVersion)
			}
		}

		// output warning for deprecated fields
		for _, field := range fltr.GetFields() {
			deprecated, d := fields.IsDeprecated(field.Name)
			if deprecated {
				log.Warnf("%s rule uses the [%s] field which "+
					"was deprecated starting from version %s. "+
					"Please consider migrating to %s field(s) "+
					"because [%s] will be removed in future versions.",
					f.Name, field.Name, d.Since, d.Fields, field.Name)
			}
		}

		// validate the value of the event/category fields
		for field, values := range fltr.GetStringFields() {
			for _, v := range values {
				switch field {
				case fields.EvtName, fields.KevtName:
					if !event.IsKnown(v) {
						return nil, nil, ErrUnknownEventName(f.Name, v)
					}
				case fields.EvtCategory, fields.KevtCategory:
					if !event.IsCategoryKnown(v) {
						return nil, nil, ErrUnknownCategoryName(f.Name, v)
					}
				}
			}
		}

		// visit filter or sequence expressions
		// to extract approver predicates
		expr := fltr.Expr()
		if expr != nil {
			c.visitApproverPredicates(expr)
		} else {
			for _, expr := range fltr.GetSequence().Expressions {
				c.visitApproverPredicates(expr.Expr)
			}
		}

		filters[f] = fltr
	}

	if len(filters) == 0 {
		return filters, nil, nil
	}

	r := c.buildCompileResult(filters)
	if r != nil {
		r.Approvers = c.approvers
	}

	return filters, r, nil
}

func (c *compiler) visitApproverPredicates(node ql.Node) {
	walk := func(n ql.Node) {
		expr, ok := n.(*ql.BinaryExpr)
		if !ok {
			return
		}

		// skip expressions wrapped in NOT
		if c.isNegated(node, n) {
			return
		}

		lhs, ok := expr.LHS.(*ql.FieldLiteral)
		if !ok {
			return
		}

		// only extract if the rule targets interested event types
		if !c.referencesApproverEvents(node) {
			return
		}

		// extract the string value(s) from RHS
		values, ok := rhsToStrings(expr.RHS)
		if !ok {
			return
		}

		op := expr.Op.String()

		switch lhs.Field {
		case fields.RegistryPath:
			for _, v := range values {
				c.approvers.AppendKey(op, v)
			}
		case fields.FilePath:
			for _, v := range values {
				c.approvers.AppendPath(op, v)
			}
		case fields.FileExtension:
			for _, v := range values {
				c.approvers.AppendExtension(op, v)
			}
		case fields.FileName:
			for _, v := range values {
				c.approvers.AppendBase(op, v)
			}
		case fields.EvtArg:
			if lhs.Arg == params.Exe {
				for _, v := range values {
					c.approvers.AppendExecutable(op, v)
				}
			}
		}
	}
	ql.WalkFunc(node, walk)
}

// referencesTargetEvents checks whether the rule AST contains
// an event type filter for high-volume events we want to approve.
func (c *compiler) referencesApproverEvents(root ql.Node) bool {
	var found bool
	ql.WalkFunc(root, func(n ql.Node) {
		expr, ok := n.(*ql.BinaryExpr)
		if !ok {
			return
		}

		// direct event match. We also include SetFileInformation
		// to approve any paths referenced in the condition
		if c.containsEventTypes(expr, event.RegOpenKey, event.OpenThread, event.OpenProcess, event.SetFileInformation) {
			found = true
			return
		}

		// for file events require open file operation
		if expr.Op == ql.And {
			if c.containsEventTypes(expr, event.CreateFile) && c.containsFieldMatch(expr, fields.FileOperation, ql.Eq, "OPEN") {
				found = true
			}
		}
	})
	return found
}

func (c *compiler) containsEventTypes(root ql.Node, types ...event.Type) bool {
	var contains bool
	ql.WalkFunc(root, func(n ql.Node) {
		expr, ok := n.(*ql.BinaryExpr)
		if !ok {
			return
		}
		lhs, ok := expr.LHS.(*ql.FieldLiteral)
		if !ok || lhs.Field != fields.EvtName {
			return
		}

		vals, ok := rhsToStrings(expr.RHS)
		if !ok {
			return
		}

		evts := make([]event.Type, 0, len(vals))
		for _, v := range vals {
			evts = append(evts, event.NameToType(v))
		}

		for _, typ := range types {
			if slices.Contains(evts, typ) {
				contains = true
				return
			}
		}
	})
	return contains
}

func (c *compiler) containsFieldMatch(root ql.Node, field fields.Field, op ql.Token, val string) bool {
	var contains bool
	ql.WalkFunc(root, func(n ql.Node) {
		expr, ok := n.(*ql.BinaryExpr)
		if !ok {
			return
		}

		lhs, ok := expr.LHS.(*ql.FieldLiteral)
		if !ok || lhs.Field != field {
			return
		}

		if expr.Op != op {
			return
		}

		values, ok := rhsToStrings(expr.RHS)
		if !ok {
			return
		}
		for _, v := range values {
			if strings.EqualFold(v, val) {
				contains = true
				return
			}
		}
	})
	return contains
}

// isNegated walks up the AST to check if the given node
// is a direct child of a NOT unary expression.
func (c *compiler) isNegated(root ql.Node, node ql.Node) bool {
	negated := false
	ql.WalkFunc(root, func(n ql.Node) {
		unary, ok := n.(*ql.NotExpr)
		if !ok {
			return
		}
		if unary.Expr == node {
			negated = true
		}
	})
	return negated
}

func (c *compiler) buildCompileResult(filters map[*config.FilterConfig]filter.Filter) *config.RulesCompileResult {
	rs := &config.RulesCompileResult{}

	m := make(map[event.Type]bool)
	events := make([]event.Type, 0)

	for _, f := range filters {
		rs.NumberRules++
		for name, values := range f.GetStringFields() {
			for _, v := range values {
				if name == fields.EvtName || name == fields.EvtCategory {
					types := event.NameToTypes(v)
					for _, typ := range types {
						switch typ.Category() {
						case event.Process:
							rs.HasProcEvents = true
						case event.Thread:
							rs.HasThreadEvents = true
						case event.Module:
							rs.HasModuleEvents = true
						case event.File:
							rs.HasFileEvents = true
						case event.Net:
							rs.HasNetworkEvents = true
						case event.Registry:
							rs.HasRegistryEvents = true
						case event.Mem:
							rs.HasMemEvents = true
						case event.Handle:
							rs.HasHandleEvents = true
						case event.Threadpool:
							rs.HasThreadpoolEvents = true
						}
						if typ.Subcategory() == event.DNS {
							rs.HasDNSEvents = true
						}
						if typ == event.MapViewFile || typ == event.UnmapViewFile {
							rs.HasVAMapEvents = true
						}
						if typ == event.OpenProcess || typ == event.OpenThread || typ == event.SetThreadContext ||
							typ == event.CreateSymbolicLinkObject {
							rs.HasAuditAPIEvents = true
						}

						if m[typ] {
							continue
						}

						events = append(events, typ)
						m[typ] = true
					}
				}
			}
		}
	}

	rs.UsedEvents = events

	return rs
}

func rhsToStrings(n ql.Node) ([]string, bool) {
	switch v := n.(type) {
	case *ql.StringLiteral:
		return []string{v.Value}, true
	case *ql.ListLiteral:
		return v.Values, true
	}
	return []string{}, false
}
