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
	"github.com/rabbitstack/fibratus/pkg/util/bitmap"
)

const excludedEvents = "eventsource.blacklist.events"
const excludedProcesses = "eventsource.blacklist.images"

// EventFilter defines the dropped event types bitmap and the processes exclusion map.
type EventFilter struct {
	Types     bitmap.Bitmap[event.Type]
	Processes map[string]bool
}

// BaseEventSourceConfig contains platform-neutral event source configuration.
type BaseEventSourceConfig struct {
	EventFilter
	// ExcludedEvents are kernel event names that will be dropped from the kernel event stream.
	ExcludedEvents []string `json:"blacklist.events" yaml:"blacklist.events"`
	// ExcludedProcesses are process image names that will be rejected if they generate a kernel event.
	ExcludedProcesses []string `json:"blacklist.images" yaml:"blacklist.images"`
}

// Init initializes event and process exclusion rules.
func (c *BaseEventSourceConfig) Init() {
	c.EventFilter.Processes = make(map[string]bool)

	for _, name := range c.ExcludedEvents {
		if typ, ok := event.ParseType(name); ok {
			c.EventFilter.Types.Set(typ)
		}
	}

	for _, name := range c.ExcludedProcesses {
		c.EventFilter.Processes[name] = true
	}
}

// SetDropMask inserts the event mask in the bitset to
// instruct the given event type should be dropped from
// the event stream.
func (c *EventSourceConfig) SetDropMask(typ event.Type) {
	c.EventFilter.Types.Set(typ)
}

// TestDropMask checks if the specified event type has
// the drop mask in the bitset.
func (c *EventSourceConfig) TestDropMask(typ event.Type) bool {
	return c.EventFilter.Types.Has(typ)
}

// ExcludeEvent determines whether the event type is declared
// in the exclusion list.
func (c *EventSourceConfig) ExcludeEvent(typ event.Type) bool {
	return c.EventFilter.Types.Has(typ)
}

// ExcludeProcess determines whether the event is excluded by the
// originating process name.
func (c *EventSourceConfig) ExcludeProcess(ps *pstypes.PS) bool {
	return ps != nil && c.EventFilter.Processes[ps.Name]
}
