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

	semver "github.com/hashicorp/go-version"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/ruleset"
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
	psnap  ps.Snapshotter
	config *config.Config
}

func newCompiler(psnap ps.Snapshotter, config *config.Config) *compiler {
	return &compiler{psnap: psnap, config: config}
}

func (c *compiler) compile(rs *ruleset.RuleSet) (map[*ruleset.Rule]filter.Filter, *ruleset.CompileResult, error) {
	filtersCount.Set(0)
	filters := make(map[*ruleset.Rule]filter.Filter)

	for _, r := range rs.Rules {
		if !r.IsBehaviour() {
			continue
		}
		if r.IsDisabled() {
			log.Warnf("[%s] rule is disabled", r.Name)
			continue
		}

		filtersCount.Add(1)

		// compile the filter
		fltr := filter.New(r.Condition, c.config, rs, filter.WithPSnapshotter(c.psnap))
		err := fltr.Compile()
		if err != nil {
			return nil, nil, ErrInvalidFilter(r.Name, err)
		}
		// check version requirements
		if !version.IsDev() {
			minEngineVer, err := semver.NewSemver(r.MinEngineVersion)
			if err != nil {
				return nil, nil, ErrMalformedMinEngineVer(r.Name, r.MinEngineVersion, err)
			}
			if minEngineVer.GreaterThan(version.Sem()) {
				return nil, nil, ErrIncompatibleFilter(r.Name, r.MinEngineVersion)
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
					r.Name, field.Name, d.Since, d.Fields, field.Name)
			}
		}

		// validate the value of the event/category fields
		for field, values := range fltr.GetStringFields() {
			for _, v := range values {
				switch field {
				case fields.EvtName, fields.KevtName:
					if !event.IsKnown(v) {
						return nil, nil, ErrUnknownEventName(r.Name, v)
					}
				case fields.EvtCategory, fields.KevtCategory:
					if !event.IsCategoryKnown(v) {
						return nil, nil, ErrUnknownCategoryName(r.Name, v)
					}
				}
			}
		}

		filters[r] = fltr
	}

	if len(filters) == 0 {
		return filters, nil, nil
	}

	return filters, c.buildCompileResult(filters), nil
}

func (c *compiler) buildCompileResult(filters map[*ruleset.Rule]filter.Filter) *ruleset.CompileResult {
	rs := &ruleset.CompileResult{}

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
						case event.Image:
							rs.HasImageEvents = true
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
