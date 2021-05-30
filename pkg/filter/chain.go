/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package filter

import (
	"bytes"
	"encoding/base64"
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/funcmap"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
	"strings"
	"text/template"
)

var (
	excludeOrFilterMatches  = expvar.NewMap("filter.chain.exclude.or.matches")
	excludeAndFilterMatches = expvar.NewMap("filter.chain.exclude.and.matches")
	includeOrFilterMatches  = expvar.NewMap("filter.chain.include.or.matches")
	includeAndFilterMatches = expvar.NewMap("filter.chain.include.and.matches")
	filterGroupsCount       = expvar.NewInt("filter.chain.groups.count")
	filtersCount            = expvar.NewInt("filter.chain.filters.count")
)

// Chain stores the compiled filter groups
// and for each incoming event, it applies
// the corresponding filtering policies to
// the event, dropping the event or passing
// it accordingly.
type Chain struct {
	filterGroups map[uint32]filterGroups
	config       *config.Config
}

type filterGroup struct {
	group   config.FilterGroup
	filters []compiledFilter
}

type compiledFilter struct {
	filter Filter
	config *config.FilterConfig
}

func (f compiledFilter) run(kevt *kevent.Kevent) bool {
	return f.filter.Run(kevt)
}

type filterGroups []*filterGroup

func (groups filterGroups) hasIncludePolicy(kevt *kevent.Kevent) bool {
	for _, g := range groups {
		if g.group.Selector.Type == kevt.Type ||
			g.group.Selector.Category == kevt.Category {
			if g.group.Policy == config.IncludePolicy {
				return true
			}
		}
	}
	return false
}

// NewChain produces a fresh filter chain.
func NewChain(c *config.Config) Chain {
	chain := Chain{
		filterGroups: make(map[uint32]filterGroups),
		config:       c,
	}
	return chain
}

// Compile loads the filter groups from all files
// and creates the filters for each filter group.
func (c *Chain) Compile() error {
	groups, err := c.config.Filters.LoadGroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if !group.Enabled {
			continue
		}
		filterGroupsCount.Add(1)
		// compute the key hash depending
		// on whether the type or category
		// were supplied in the selector
		sel := group.Selector
		key := sel.Type.Hash()
		if key == 0 {
			key = sel.Category.Hash()
		}
		// compile filters
		filters := make([]compiledFilter, 0, len(group.FromStrings))
		for _, filterConfig := range group.FromStrings {
			f := New(filterConfig.Def, c.config)
			if err := f.Compile(); err != nil {
				return fmt.Errorf("invalid filter %q in %q group: %v",
					filterConfig.Name, group.Name, err)
			}
			filters = append(
				filters,
				compiledFilter{config: filterConfig, filter: f},
			)
			filtersCount.Add(1)
		}
		c.filterGroups[key] = append(
			c.filterGroups[key],
			&filterGroup{group: group, filters: filters},
		)
	}
	return nil
}

func (c *Chain) findFilterGroups(kevt *kevent.Kevent) filterGroups {
	groups1 := c.filterGroups[kevt.Type.Hash()]
	groups2 := c.filterGroups[kevt.Category.Hash()]
	if groups1 == nil && groups2 == nil {
		return nil
	}
	return append(groups1, groups2...)
}

func (c *Chain) Run(kevt *kevent.Kevent) bool {
	// if there are no filter groups
	// we assume no group files were
	// defined or specified in the config
	// so, the default behaviour in such
	// cases is to pass the event and
	// hand over it to the CLI filter
	if len(c.filterGroups) == 0 {
		return true
	}
	// get filter groups for particular
	// kevent type or category.
	// Events/categories without filter
	// groups are dropped by default
	groups := c.findFilterGroups(kevt)
	if len(groups) == 0 {
		return false
	}
	// exclude policies take precedence over
	// groups with include policies, so we first
	// evaluate those. If no filter matches occur,
	// we let pass the event but only if there are
	// no groups with include policies
	ok := runGroups(groups, config.ExcludePolicy, kevt)
	if ok {
		return false
	}

	if !groups.hasIncludePolicy(kevt) {
		return true
	}

	// finally we apply include policies, as at
	// this point none of the groups with exclude
	// policies got matched
	return runGroups(groups, config.IncludePolicy, kevt)
}

func runGroups(groups filterGroups, policy config.FilterGroupPolicy, kevt *kevent.Kevent) bool {
nextGroup:
	for _, g := range groups {
		if g.group.Policy != policy {
			continue
		}
		// stores the result of the 'and' relation
		var andMatched bool
		// for each filter group we traverse the
		// filters. Depending on the group policy
		// and relation we act accordingly
		for _, f := range g.filters {
			// execute filter
			ok := f.run(kevt)
			// apply group policies and
			// for each policy their two
			// possible relation types
			switch g.group.Policy {
			case config.ExcludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if ok {
						excludeOrFilterMatches.Add(f.config.Name, 1)
						return true
					}
				case config.AndRelation:
					if !ok {
						// jump to the next exclude group
						continue nextGroup
					}
					andMatched = true
				}

			case config.IncludePolicy:
				switch g.group.Relation {
				case config.OrRelation:
					if ok {
						includeOrFilterMatches.Add(f.config.Name, 1)
						err := runFilterAction(kevt, g.group, f.config)
						if err != nil {
							log.Warnf("unable to execute %q filter action: %v", f.config.Name, err)
						}
						return true
					}
				case config.AndRelation:
					if !ok {
						// jump to the next include group
						continue nextGroup
					}
					andMatched = true
				}
			}
		}
		// got a match on the and relation group
		if andMatched {
			switch g.group.Policy {
			case config.ExcludePolicy:
				for _, f := range g.filters {
					excludeAndFilterMatches.Add(f.config.Name, 1)
				}
			case config.IncludePolicy:
				for _, f := range g.filters {
					includeAndFilterMatches.Add(f.config.Name, 1)
					err := runFilterAction(kevt, g.group, f.config)
					if err != nil {
						log.Warnf("unable to execute %q filter action: %v", f.config.Name, err)
					}
				}
			}
			return true
		}
	}

	return false
}

// ActionContext is the convenient structure
// for grouping the event that resulted in
// matched filter along with filter group
// information.
type ActionContext struct {
	Kevt   *kevent.Kevent
	Filter *config.FilterConfig
	Group  config.FilterGroup
}

// runFilterAction executes the template associated with the filter
// that has producing a match in one of the include groups.
func runFilterAction(kevt *kevent.Kevent, group config.FilterGroup, filter *config.FilterConfig) error {
	if filter.Action == "" {
		return nil
	}
	action, err := base64.StdEncoding.DecodeString(filter.Action)
	if err != nil {
		return fmt.Errorf("corrupted filter action: %v", err)
	}

	fmap := funcmap.New()
	funcmap.InitFuncs(fmap)
	tmpl, err := template.New(filter.Name).Funcs(fmap).Parse(string(action))
	if err != nil {
		return err
	}
	ctx := &ActionContext{
		Kevt:   kevt,
		Filter: filter,
		Group:  group,
	}
	var bb bytes.Buffer
	if err := tmpl.Execute(&bb, ctx); err != nil {
		return err
	}
	if strings.TrimSpace(bb.String()) != "" {
		return errors.New(bb.String())
	}
	return nil
}
