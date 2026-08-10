//go:build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"runtime"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	enableThreadEvents     = "eventsource.enable-thread"
	enableRegistryEvents   = "eventsource.enable-registry"
	enableNetEvents        = "eventsource.enable-net"
	enableFileIOEvents     = "eventsource.enable-fileio"
	enableVAMapEvents      = "eventsource.enable-vamap"
	enableModuleEvents     = "eventsource.enable-module"
	enableHandleEvents     = "eventsource.enable-handle"
	enableMemEvents        = "eventsource.enable-mem"
	enableAuditAPIEvents   = "eventsource.enable-audit-api"
	enableDNSEvents        = "eventsource.enable-dns"
	enableThreadpoolEvents = "eventsource.enable-threadpool"
	stackEnrichment        = "eventsource.stack-enrichment"
	bufferSize             = "eventsource.buffer-size"
	minBuffers             = "eventsource.min-buffers"
	maxBuffers             = "eventsource.max-buffers"
	flushInterval          = "eventsource.flush-interval"
	excludedEvents         = "eventsource.blacklist.events"
	excludedImages         = "eventsource.blacklist.images"
	maxBufferSize          = uint32(512)
)

var (
	defaultMinBuffers    = uint32(runtime.NumCPU() * 2)
	defaultMaxBuffers    = uint32(runtime.NumCPU() * 8)
	defaultFlushInterval = time.Second
)

type EventSourceConfig struct {
	eventSourceConfig

	ExcludedEvents         []string      `json:"blacklist.events" yaml:"blacklist.events"`
	ExcludedImages         []string      `json:"blacklist.images" yaml:"blacklist.images"`
	EnableThreadEvents     bool          `json:"enable-thread" yaml:"enable-thread"`
	EnableRegistryEvents   bool          `json:"enable-registry" yaml:"enable-registry"`
	EnableNetEvents        bool          `json:"enable-net" yaml:"enable-net"`
	EnableFileIOEvents     bool          `json:"enable-fileio" yaml:"enable-fileio"`
	EnableVAMapEvents      bool          `json:"enable-vamap" yaml:"enable-vamap"`
	EnableModuleEvents     bool          `json:"enable-image" yaml:"enable-module"`
	EnableHandleEvents     bool          `json:"enable-handle" yaml:"enable-handle"`
	EnableMemEvents        bool          `json:"enable-memory" yaml:"enable-memory"`
	EnableAuditAPIEvents   bool          `json:"enable-audit-api" yaml:"enable-audit-api"`
	EnableDNSEvents        bool          `json:"enable-dns" yaml:"enable-dns"`
	EnableThreadpoolEvents bool          `json:"enable-threadpool" yaml:"enable-threadpool"`
	StackEnrichment        bool          `json:"stack-enrichment" yaml:"stack-enrichment"`
	BufferSize             uint32        `json:"buffer-size" yaml:"buffer-size"`
	MinBuffers             uint32        `json:"min-buffers" yaml:"min-buffers"`
	MaxBuffers             uint32        `json:"max-buffers" yaml:"max-buffers"`
	FlushTimer             time.Duration `json:"flush-interval" yaml:"flush-interval"`
}

func (c *EventSourceConfig) AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enableThreadEvents, true, "Determines whether thread events are collected")
	flags.Bool(enableRegistryEvents, true, "Determines whether registry events are collected")
	flags.Bool(enableNetEvents, true, "Determines whether network events are collected")
	flags.Bool(enableFileIOEvents, true, "Determines whether file I/O events are collected")
	flags.Bool(enableVAMapEvents, true, "Determines whether VA map/unmap events are collected")
	flags.Bool(enableModuleEvents, true, "Determines whether module events are collected")
	flags.Bool(enableHandleEvents, false, "Determines whether handle events are collected")
	flags.Bool(enableMemEvents, true, "Determines whether memory events are collected")
	flags.Bool(enableAuditAPIEvents, true, "Determines whether audit API events are collected")
	flags.Bool(enableDNSEvents, true, "Determines whether DNS events are collected")
	flags.Bool(enableThreadpoolEvents, true, "Determines whether thread pool events are collected")
	flags.Bool(stackEnrichment, true, "Indicates if stack enrichment is enabled")
	flags.Int(bufferSize, int(maxBufferSize), "Represents the trace buffer size in kilobytes")
	flags.Int(minBuffers, int(defaultMinBuffers), "Determines the minimum trace buffer count")
	flags.Int(maxBuffers, int(defaultMaxBuffers), "Determines the maximum trace buffer count")
	flags.Duration(flushInterval, defaultFlushInterval, "Specifies how often trace buffers are flushed")
	flags.StringSlice(excludedEvents, nil, "A list of event names to drop")
	flags.StringSlice(excludedImages, nil, "A list of image names to drop")
}

func (c *EventSourceConfig) initFromViper(v *viper.Viper) {
	c.EnableThreadEvents = v.GetBool(enableThreadEvents)
	c.EnableRegistryEvents = v.GetBool(enableRegistryEvents)
	c.EnableNetEvents = v.GetBool(enableNetEvents)
	c.EnableFileIOEvents = v.GetBool(enableFileIOEvents)
	c.EnableVAMapEvents = v.GetBool(enableVAMapEvents)
	c.EnableModuleEvents = v.GetBool(enableModuleEvents)
	c.EnableHandleEvents = v.GetBool(enableHandleEvents)
	c.EnableMemEvents = v.GetBool(enableMemEvents)
	c.EnableAuditAPIEvents = v.GetBool(enableAuditAPIEvents)
	c.EnableDNSEvents = v.GetBool(enableDNSEvents)
	c.EnableThreadpoolEvents = v.GetBool(enableThreadpoolEvents)
	c.StackEnrichment = v.GetBool(stackEnrichment)
	c.BufferSize = uint32(v.GetInt(bufferSize))
	c.MinBuffers = uint32(v.GetInt(minBuffers))
	c.MaxBuffers = uint32(v.GetInt(maxBuffers))
	c.FlushTimer = v.GetDuration(flushInterval)
	c.ExcludedEvents = v.GetStringSlice(excludedEvents)
	c.ExcludedImages = v.GetStringSlice(excludedImages)
	c.Init()
}

func platformEventTypes() []event.Type { return event.AllWithState() }
