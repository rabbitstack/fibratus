/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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

package config

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/bitmask"
)

type eventSourceConfig struct {
	dropMasks      *bitmask.Bitmask
	allMasks       *bitmask.Bitmask
	excludedImages map[string]bool
}

func (c *EventSourceConfig) initEventMasks(types []event.Type) {
	c.dropMasks = bitmask.New()
	c.allMasks = bitmask.New()
	c.excludedImages = make(map[string]bool)

	for _, name := range c.ExcludedEvents {
		for _, typ := range event.NameToTypes(name) {
			if typ != event.UnknownType {
				c.dropMasks.Set(typ.ID())
			}
		}
	}
	for _, typ := range types {
		c.allMasks.Set(typ.ID())
	}
	for _, name := range c.ExcludedImages {
		c.excludedImages[name] = true
	}
}

// Init initializes event and image exclusion maps.
func (c *EventSourceConfig) Init() {
	c.initEventMasks(platformEventTypes())
}

func (c *EventSourceConfig) SetDropMask(typ event.Type) {
	if c.dropMasks == nil {
		c.dropMasks = bitmask.New()
	}
	c.dropMasks.Set(typ.ID())
}

func (c *EventSourceConfig) TestDropMask(typ event.Type) bool {
	return c.dropMasks != nil && c.dropMasks.IsSet(typ.ID())
}

func (c *EventSourceConfig) ExcludeEvent(id uint) bool {
	return c.dropMasks != nil && c.dropMasks.IsSet(id)
}

func (c *EventSourceConfig) EventExists(id uint) bool {
	return c.allMasks != nil && c.allMasks.IsSet(id)
}

func (c *EventSourceConfig) ExcludeImage(ps *pstypes.PS) bool {
	return ps != nil && c.excludedImages[ps.Name]
}
