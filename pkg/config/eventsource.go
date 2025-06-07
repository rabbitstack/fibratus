//go:build windows
// +build windows

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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/util/bitmask"
	"runtime"
	"time"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/spf13/viper"
)

const (
	enableThreadEvents     = "eventsource.enable-thread"
	enableRegistryEvents   = "eventsource.enable-registry"
	enableNetEvents        = "eventsource.enable-net"
	enableFileIOEvents     = "eventsource.enable-fileio"
	enableVAMapEvents      = "eventsource.enable-vamap"
	enableImageEvents      = "eventsource.enable-image"
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

	excludedEvents = "eventsource.blacklist.events"
	excludedImages = "eventsource.blacklist.images"

	maxBufferSize = uint32(512)
)

var (
	defaultMinBuffers    = uint32(runtime.NumCPU() * 2)
	defaultMaxBuffers    = defaultMinBuffers + 20
	defaultFlushInterval = time.Second
)

// EventSourceConfig stores different configuration options for fine-tuning the event source.
type EventSourceConfig struct {
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
	// EnableImageEvents indicates if image events are collected by the ETW provider.
	EnableImageEvents bool `json:"enable-image" yaml:"enable-image"`
	// EnableHandleEvents indicates whether handle creation/disposal events are enabled.
	EnableHandleEvents bool `json:"enable-handle" yaml:"enable-handle"`
	// EnableMemEvents indicates whether memory manager events are enabled.
	EnableMemEvents bool `json:"enable-memory" yaml:"enable-memory"`
	// EnableAuditAPIEvents indicates if kernel audit API calls events are enabled
	EnableAuditAPIEvents bool `json:"enable-audit-api" yaml:"enable-audit-api"`
	// EnableDNSEvents indicates if DNS client events are enabled
	EnableDNSEvents bool `json:"enable-dns" yaml:"enable-dns"`
	// EnableThreadpoolEvents indicates if thread pool events are enabled
	EnableThreadpoolEvents bool `json:"enable-threadpool" yaml:"enable-threadpool"`
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
	// ExcludedEvents are kernel event names that will be dropped from the kernel event stream.
	ExcludedEvents []string `json:"blacklist.events" yaml:"blacklist.events"`
	// ExcludedImages are process image names that will be rejected if they generate a kernel event.
	ExcludedImages []string `json:"blacklist.images" yaml:"blacklist.images"`

	dropMasks *bitmask.Bitmask
	allMasks  *bitmask.Bitmask

	excludedImages map[string]bool
}

func (c *EventSourceConfig) initFromViper(v *viper.Viper) {
	c.EnableThreadEvents = v.GetBool(enableThreadEvents)
	c.EnableRegistryEvents = v.GetBool(enableRegistryEvents)
	c.EnableNetEvents = v.GetBool(enableNetEvents)
	c.EnableFileIOEvents = v.GetBool(enableFileIOEvents)
	c.EnableVAMapEvents = v.GetBool(enableVAMapEvents)
	c.EnableImageEvents = v.GetBool(enableImageEvents)
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

	c.dropMasks = bitmask.New()
	c.allMasks = bitmask.New()

	c.excludedImages = make(map[string]bool)

	for _, name := range c.ExcludedEvents {
		if typ := event.NameToType(name); typ != event.UnknownType {
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

// Init is an exported method to allow initializing exclusion maps from external modules.
func (c *EventSourceConfig) Init() {
	c.excludedImages = make(map[string]bool)

	if c.dropMasks == nil {
		c.dropMasks = bitmask.New()
	}
	for _, name := range c.ExcludedEvents {
		for _, typ := range event.NameToTypes(name) {
			if typ != event.UnknownType {
				c.dropMasks.Set(typ.ID())
			}
		}
	}

	for _, name := range c.ExcludedImages {
		c.excludedImages[name] = true
	}

	if c.allMasks == nil {
		c.allMasks = bitmask.New()
	}
	for _, typ := range event.AllWithState() {
		c.allMasks.Set(typ.ID())
	}
}

// SetDropMask inserts the event mask in the bitset to
// instruct the given event type should be dropped from
// the event stream.
func (c *EventSourceConfig) SetDropMask(typ event.Type) {
	c.dropMasks.Set(typ.ID())
}

// TestDropMask checks if the specified event type has
// the drop mask in the bitset.
func (c *EventSourceConfig) TestDropMask(typ event.Type) bool {
	return c.dropMasks.IsSet(typ.ID())
}

// ExcludeEvent determines whether the supplied short
// event ID exists in the bitset of excluded events.
func (c *EventSourceConfig) ExcludeEvent(id uint) bool {
	return c.dropMasks.IsSet(id)
}

// EventExists determines if the provided event ID exists
// in the internal event catalog by checking the event ID
// bitmask.
func (c *EventSourceConfig) EventExists(id uint) bool {
	return c.allMasks.IsSet(id)
}

// ExcludeImage determines whether the process generating event is present in the
// list of excluded images. If the hit occurs, the event associated with the process
// is dropped.
func (c *EventSourceConfig) ExcludeImage(ps *pstypes.PS) bool {
	if len(c.excludedImages) == 0 {
		return false
	}
	if ps == nil {
		return false
	}
	return c.excludedImages[ps.Name]
}
