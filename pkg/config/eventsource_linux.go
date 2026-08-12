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
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	enableFileIOEvents = "eventsource.enable-fileio"
	enableNetEvents    = "eventsource.enable-net"
	enableMemEvents    = "eventsource.enable-mem"
	excludedEvents     = "eventsource.blacklist.events"
	excludedImages     = "eventsource.blacklist.images"
)

type EventSourceConfig struct {
	eventSourceConfig

	ExcludedEvents     []string `json:"blacklist.events" yaml:"blacklist.events"`
	ExcludedImages     []string `json:"blacklist.images" yaml:"blacklist.images"`
	EnableFileIOEvents bool     `json:"enable-fileio" yaml:"enable-fileio"`
	EnableNetEvents    bool     `json:"enable-net" yaml:"enable-net"`
	EnableMemEvents    bool     `json:"enable-mem" yaml:"enable-mem"`
}

func (c *EventSourceConfig) AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enableFileIOEvents, true, "Determines whether file events are collected")
	flags.Bool(enableNetEvents, true, "Determines whether network events are collected")
	flags.Bool(enableMemEvents, true, "Determines whether memory events are collected")
	flags.StringSlice(excludedEvents, nil, "A list of event names to drop")
	flags.StringSlice(excludedImages, nil, "A list of image names to drop")
}

func (c *EventSourceConfig) initFromViper(v *viper.Viper) {
	c.EnableFileIOEvents = v.GetBool(enableFileIOEvents)
	c.EnableNetEvents = v.GetBool(enableNetEvents)
	c.EnableMemEvents = v.GetBool(enableMemEvents)
	c.ExcludedEvents = v.GetStringSlice(excludedEvents)
	c.ExcludedImages = v.GetStringSlice(excludedImages)
	c.Init()
}

func platformEventTypes() []event.Type { return event.All() }
