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

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	enableThreadEvents   = "eventsource.enable-thread"
	enableRegistryEvents = "eventsource.enable-registry"
	enableNetEvents      = "eventsource.enable-net"
	enableFileIOEvents   = "eventsource.enable-fileio"
	enableVAMapEvents    = "eventsource.enable-vamap"
	enableModuleEvents   = "eventsource.enable-module"
	enableMemEvents      = "eventsource.enable-mem"
	enableAuditAPIEvents = "eventsource.enable-audit-api"
	enableDNSEvents      = "eventsource.enable-dns"
	stackEnrichment      = "eventsource.stack-enrichment"
	bufferSize           = "eventsource.buffer-size"
	minBuffers           = "eventsource.min-buffers"
	maxBuffers           = "eventsource.max-buffers"
	flushInterval        = "eventsource.flush-interval"

	maxBufferSize = uint32(512)
)

var (
	defaultMinBuffers    = uint32(runtime.NumCPU() * 2)
	defaultMaxBuffers    = uint32(runtime.NumCPU() * 8)
	defaultFlushInterval = time.Second
)

// EventSourceConfig stores different configuration options for fine-tuning the event source.
type EventSourceConfig struct {
	BaseEventSourceConfig
	// EnableThreadEvents indicates if thread events are collected by the ETW provider.
	EnableThreadEvents bool `json:"enable-thread" yaml:"enable-thread"`
	// EnableRegistryEvents indicates if registry events are collected by the ETW provider.
	EnableRegistryEvents bool `json:"enable-registry" yaml:"enable-registry"`
	// EnableNetEvents determines whether network (TCP/UDP) events are collected by the ETW provider.
	EnableNetEvents bool `json:"enable-net" yaml:"enable-net"`
	// EnableFileIOEvents indicates if file I/O events are collected by the ETW provider.
	EnableFileIOEvents bool `json:"enable-fileio" yaml:"enable-fileio"`
	// EnableVAMapEvents indicates if VA map/unmap events are collected by the ETW provider.
	EnableVAMapEvents bool `json:"enable-vamap" yaml:"enable-vamap"`
	// EnableModuleEvents indicates if module events are collected by the ETW provider.
	EnableModuleEvents bool `json:"enable-image" yaml:"enable-module"`
	// EnableMemEvents indicates whether memory manager events are enabled.
	EnableMemEvents bool `json:"enable-memory" yaml:"enable-memory"`
	// EnableAuditAPIEvents indicates if kernel audit API calls events are enabled
	EnableAuditAPIEvents bool `json:"enable-audit-api" yaml:"enable-audit-api"`
	// EnableDNSEvents indicates if DNS client events are enabled
	EnableDNSEvents bool `json:"enable-dns" yaml:"enable-dns"`
	// StackEnrichment indicates if stack enrichment is enabled for eligible events.
	StackEnrichment bool `json:"stack-enrichment" yaml:"stack-enrichment"`
	// BufferSize represents the amount of memory allocated for each event tracing session buffer, in kilobytes.
	// The buffer size affects the rate at which buffers fill and must be flushed (small buffer size requires
	// less memory, but it increases the rate at which buffers must be flushed).
	BufferSize uint32 `json:"buffer-size" yaml:"buffer-size"`
	// MinBuffers determines the minimum number of buffers allocated for the event tracing session's buffer pool.
	MinBuffers uint32 `json:"min-buffers" yaml:"min-buffers"`
	// MaxBuffers is the maximum number of buffers allocated for the event tracing session's buffer pool.
	MaxBuffers uint32 `json:"max-buffers" yaml:"max-buffers"`
	// FlushTimer specifies how often the trace buffers are forcibly flushed.
	FlushTimer time.Duration `json:"flush-interval" yaml:"flush-interval"`
}

func (c *EventSourceConfig) AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enableThreadEvents, true, "Determines whether thread events are collected")
	flags.Bool(enableRegistryEvents, true, "Determines whether registry events are collected")
	flags.Bool(enableNetEvents, true, "Determines whether network events are collected")
	flags.Bool(enableFileIOEvents, true, "Determines whether file I/O events are collected")
	flags.Bool(enableVAMapEvents, true, "Determines whether VA map/unmap events are collected")
	flags.Bool(enableModuleEvents, true, "Determines whether module events are collected")
	flags.Bool(enableMemEvents, true, "Determines whether memory events are collected")
	flags.Bool(enableAuditAPIEvents, true, "Determines whether audit API events are collected")
	flags.Bool(enableDNSEvents, true, "Determines whether DNS events are collected")
	flags.Bool(stackEnrichment, true, "Indicates if stack enrichment is enabled")
	flags.Int(bufferSize, int(maxBufferSize), "Represents the trace buffer size in kilobytes")
	flags.Int(minBuffers, int(defaultMinBuffers), "Determines the minimum trace buffer count")
	flags.Int(maxBuffers, int(defaultMaxBuffers), "Determines the maximum trace buffer count")
	flags.Duration(flushInterval, defaultFlushInterval, "Specifies how often trace buffers are flushed")
	flags.StringSlice(excludedEvents, nil, "A list of event names to drop")
	flags.StringSlice(excludedProcesses, nil, "A list of image names to drop")
}

func (c *EventSourceConfig) initFromViper(v *viper.Viper) {
	c.EnableThreadEvents = v.GetBool(enableThreadEvents)
	c.EnableRegistryEvents = v.GetBool(enableRegistryEvents)
	c.EnableNetEvents = v.GetBool(enableNetEvents)
	c.EnableFileIOEvents = v.GetBool(enableFileIOEvents)
	c.EnableVAMapEvents = v.GetBool(enableVAMapEvents)
	c.EnableModuleEvents = v.GetBool(enableModuleEvents)
	c.EnableMemEvents = v.GetBool(enableMemEvents)
	c.EnableAuditAPIEvents = v.GetBool(enableAuditAPIEvents)
	c.EnableDNSEvents = v.GetBool(enableDNSEvents)
	c.StackEnrichment = v.GetBool(stackEnrichment)
	c.BufferSize = uint32(v.GetInt(bufferSize))
	c.MinBuffers = uint32(v.GetInt(minBuffers))
	c.MaxBuffers = uint32(v.GetInt(maxBuffers))
	c.FlushTimer = v.GetDuration(flushInterval)
	c.ExcludedEvents = v.GetStringSlice(excludedEvents)
	c.ExcludedProcesses = v.GetStringSlice(excludedProcesses)
	c.Init()
}
