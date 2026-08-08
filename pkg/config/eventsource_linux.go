//go:build linux

/*
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
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	enableProcessEvents = "eventsource.enable-process"
	enableFileEvents    = "eventsource.enable-file"
	enableNetEvents     = "eventsource.enable-net"
	enableMemEvents     = "eventsource.enable-mem"
	excludedEvents      = "eventsource.blacklist.events"
	excludedImages      = "eventsource.blacklist.images"
)

type EventSourceConfig struct {
	EnableProcessEvents bool     `json:"enable-process" yaml:"enable-process"`
	EnableFileIOEvents  bool     `json:"enable-file" yaml:"enable-file"`
	EnableNetEvents     bool     `json:"enable-net" yaml:"enable-net"`
	EnableMemEvents     bool     `json:"enable-mem" yaml:"enable-mem"`
	ExcludedEvents      []string `json:"blacklist.events" yaml:"blacklist.events"`
	ExcludedImages      []string `json:"blacklist.images" yaml:"blacklist.images"`

	dropMasks      *bitmask.Bitmask
	allMasks       *bitmask.Bitmask
	excludedImages map[string]bool
}

func (c *EventSourceConfig) AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enableProcessEvents, true, "Determines whether process events are collected")
	flags.Bool(enableFileEvents, true, "Determines whether file events are collected")
	flags.Bool(enableNetEvents, true, "Determines whether network events are collected")
	flags.Bool(enableMemEvents, true, "Determines whether memory events are collected")
	flags.StringSlice(excludedEvents, nil, "A list of event names to drop")
	flags.StringSlice(excludedImages, nil, "A list of image names to drop")
}

func (c *EventSourceConfig) initFromViper(v *viper.Viper) {
	c.EnableProcessEvents = v.GetBool(enableProcessEvents)
	c.EnableFileIOEvents = v.GetBool(enableFileEvents)
	c.EnableNetEvents = v.GetBool(enableNetEvents)
	c.EnableMemEvents = v.GetBool(enableMemEvents)
	c.ExcludedEvents = v.GetStringSlice(excludedEvents)
	c.ExcludedImages = v.GetStringSlice(excludedImages)
	c.Init()
}

func (c *EventSourceConfig) Init() {
	c.dropMasks = bitmask.New()
	c.allMasks = bitmask.New()
	c.excludedImages = make(map[string]bool)
	for _, name := range c.ExcludedEvents {
		for _, typ := range event.NameToTypes(name) {
			c.dropMasks.Set(typ.ID())
		}
	}
	for _, typ := range event.AllWithState() {
		c.allMasks.Set(typ.ID())
	}
	for _, name := range c.ExcludedImages {
		c.excludedImages[name] = true
	}
}

func (c *EventSourceConfig) SetDropMask(typ event.Type) { c.dropMasks.Set(typ.ID()) }
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
