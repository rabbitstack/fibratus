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
	"golang.org/x/sys/windows"
	"runtime"
	"time"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/spf13/viper"
)

const (
	enableThreadKevents    = "kstream.enable-thread"
	enableRegistryKevents  = "kstream.enable-registry"
	enableNetKevents       = "kstream.enable-net"
	enableFileIOKevents    = "kstream.enable-fileio"
	enableVAMapKevents     = "kstream.enable-vamap"
	enableImageKevents     = "kstream.enable-image"
	enableHandleKevents    = "kstream.enable-handle"
	enableMemKevents       = "kstream.enable-mem"
	enableAuditAPIEvents   = "kstream.enable-audit-api"
	enableDNSEvents        = "kstream.enable-dns"
	enableThreadpoolEvents = "kstream.enable-threadpool"
	stackEnrichment        = "kstream.stack-enrichment"
	bufferSize             = "kstream.buffer-size"
	minBuffers             = "kstream.min-buffers"
	maxBuffers             = "kstream.max-buffers"
	flushInterval          = "kstream.flush-interval"

	excludedEvents = "kstream.blacklist.events"
	excludedImages = "kstream.blacklist.images"

	maxBufferSize = uint32(512)
)

var (
	defaultMinBuffers    = uint32(runtime.NumCPU() * 2)
	defaultMaxBuffers    = defaultMinBuffers + 20
	defaultFlushInterval = time.Second
)

// KstreamConfig stores different configuration options for fine-tuning kstream consumer/controller settings.
type KstreamConfig struct {
	// EnableThreadKevents indicates if thread events are collected by the ETW provider.
	EnableThreadKevents bool `json:"enable-thread" yaml:"enable-thread"`
	// EnableRegistryKevents indicates if registry events are collected by the ETW provider.
	EnableRegistryKevents bool `json:"enable-registry" yaml:"enable-registry"`
	// EnableNetKevents determines whether network (TCP/UDP) events are collected by the ETW provider.
	EnableNetKevents bool `json:"enable-net" yaml:"enable-net"`
	// EnableFileIOKevents indicates if file I/O events are collected by the ETW provider.
	EnableFileIOKevents bool `json:"enable-fileio" yaml:"enable-fileio"`
	// EnableVAMapKevents indicates if VA map/unmap events are collected by the ETW provider.
	EnableVAMapKevents bool `json:"enable-vamap" yaml:"enable-vamap"`
	// EnableImageKevents indicates if image events are collected by the ETW provider.
	EnableImageKevents bool `json:"enable-image" yaml:"enable-image"`
	// EnableHandleKevents indicates whether handle creation/disposal events are enabled.
	EnableHandleKevents bool `json:"enable-handle" yaml:"enable-handle"`
	// EnableMemKevents indicates whether memory manager events are enabled.
	EnableMemKevents bool `json:"enable-memory" yaml:"enable-memory"`
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
	// ExcludedKevents are kernel event names that will be dropped from the kernel event stream.
	ExcludedKevents []string `json:"blacklist.events" yaml:"blacklist.events"`
	// ExcludedImages are process image names that will be rejected if they generate a kernel event.
	ExcludedImages []string `json:"blacklist.images" yaml:"blacklist.images"`

	dropMasks event.EventsetMasks

	excludedImages map[string]bool
}

func (c *KstreamConfig) initFromViper(v *viper.Viper) {
	c.EnableThreadKevents = v.GetBool(enableThreadKevents)
	c.EnableRegistryKevents = v.GetBool(enableRegistryKevents)
	c.EnableNetKevents = v.GetBool(enableNetKevents)
	c.EnableFileIOKevents = v.GetBool(enableFileIOKevents)
	c.EnableVAMapKevents = v.GetBool(enableVAMapKevents)
	c.EnableImageKevents = v.GetBool(enableImageKevents)
	c.EnableHandleKevents = v.GetBool(enableHandleKevents)
	c.EnableMemKevents = v.GetBool(enableMemKevents)
	c.EnableAuditAPIEvents = v.GetBool(enableAuditAPIEvents)
	c.EnableDNSEvents = v.GetBool(enableDNSEvents)
	c.EnableThreadpoolEvents = v.GetBool(enableThreadpoolEvents)
	c.StackEnrichment = v.GetBool(stackEnrichment)
	c.BufferSize = uint32(v.GetInt(bufferSize))
	c.MinBuffers = uint32(v.GetInt(minBuffers))
	c.MaxBuffers = uint32(v.GetInt(maxBuffers))
	c.FlushTimer = v.GetDuration(flushInterval)
	c.ExcludedKevents = v.GetStringSlice(excludedEvents)
	c.ExcludedImages = v.GetStringSlice(excludedImages)

	c.excludedImages = make(map[string]bool)

	for _, name := range c.ExcludedKevents {
		if typ := event.NameToType(name); typ != event.UnknownType {
			c.dropMasks.Set(typ)
		}
	}
	for _, name := range c.ExcludedImages {
		c.excludedImages[name] = true
	}
}

// Init is an exported method to allow initializing exclusion maps from external modules.
func (c *KstreamConfig) Init() {
	c.excludedImages = make(map[string]bool)
	for _, name := range c.ExcludedKevents {
		for _, typ := range event.NameToTypes(name) {
			if typ != event.UnknownType {
				c.dropMasks.Set(typ)
			}
		}
	}
	for _, name := range c.ExcludedImages {
		c.excludedImages[name] = true
	}
}

// SetDropMask inserts the event mask in the bitset to
// instruct the given event type should be dropped from
// the event stream.
func (c *KstreamConfig) SetDropMask(Type event.Type) {
	c.dropMasks.Set(Type)
}

// TestDropMask checks if the specified event type has
// the drop mask in the bitset.
func (c *KstreamConfig) TestDropMask(Type event.Type) bool {
	return c.dropMasks.Test(Type.GUID(), Type.HookID())
}

// ExcludeKevent determines whether the supplied provider GUID
// and the hook identifier are in the bitset of excluded events.
func (c *KstreamConfig) ExcludeKevent(guid windows.GUID, hookID uint16) bool {
	return c.dropMasks.Test(guid, hookID)
}

// ExcludeImage determines whether the process generating event is present in the
// list of excluded images. If the hit occurs, the event associated with the process
// is dropped.
func (c *KstreamConfig) ExcludeImage(ps *pstypes.PS) bool {
	if len(c.excludedImages) == 0 {
		return false
	}
	if ps == nil {
		return false
	}
	return c.excludedImages[ps.Name]
}
