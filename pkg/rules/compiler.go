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
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
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
)

type compiler struct {
	psnap  ps.Snapshotter
	config *config.Config
}

func newCompiler(psnap ps.Snapshotter, config *config.Config) *compiler {
	return &compiler{psnap: psnap, config: config}
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
					f.Name, field, d.Since, d.Fields, field)
			}
		}

		filters[f] = fltr
	}

	if len(filters) == 0 {
		return filters, nil, nil
	}

	return filters, c.buildCompileResult(filters), nil
}

func (c *compiler) buildCompileResult(filters map[*config.FilterConfig]filter.Filter) *config.RulesCompileResult {
	rs := &config.RulesCompileResult{}

	m := make(map[ktypes.Ktype]bool)
	events := make([]ktypes.Ktype, 0)

	for _, f := range filters {
		rs.NumberRules++
		for name, values := range f.GetStringFields() {
			for _, v := range values {
				if name == fields.KevtName || name == fields.KevtCategory {
					types := ktypes.KeventNameToKtypes(v)
					for _, typ := range types {
						switch typ.Category() {
						case ktypes.Process:
							rs.HasProcEvents = true
						case ktypes.Thread:
							rs.HasThreadEvents = true
						case ktypes.Image:
							rs.HasImageEvents = true
						case ktypes.File:
							rs.HasFileEvents = true
						case ktypes.Net:
							rs.HasNetworkEvents = true
						case ktypes.Registry:
							rs.HasRegistryEvents = true
						case ktypes.Mem:
							rs.HasMemEvents = true
						case ktypes.Handle:
							rs.HasHandleEvents = true
						case ktypes.Threadpool:
							rs.HasThreadpoolEvents = true
						}
						if typ.Subcategory() == ktypes.DNS {
							rs.HasDNSEvents = true
						}
						if typ == ktypes.MapViewFile || typ == ktypes.UnmapViewFile {
							rs.HasVAMapEvents = true
						}
						if typ == ktypes.OpenProcess || typ == ktypes.OpenThread || typ == ktypes.SetThreadContext ||
							typ == ktypes.CreateSymbolicLinkObject {
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
