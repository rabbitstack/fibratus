/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package etw

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// ProviderInfo describes ETW provider metadata.
type ProviderInfo struct {
	// GUID is the globally unique identifier for the
	// ETW provider for which the session is started.
	GUID windows.GUID
	// Keywords is the bitmask of keywords that determine
	// the categories of events for the provider to emit.
	// The provider typically writes an event if the event's
	// keyword bits match any of the bits set in this value
	// or if the event has no keyword bits set. Only relevant
	// for providers that are enabled via etw.EnableProvider
	// API.
	Keywords uint64
	// EnableStacks indicates if callstacks are enabled for
	// this provider.
	EnableStacks bool
	// CaptureState requests that the provider log its state
	// information, such as rundown events.
	CaptureState bool
	//eventFilterDescriptors stores the provider-specific filters.
	eventFilterDescriptors []etw.EventFilterDescriptor
}

func (p *ProviderInfo) HasEventFilterDescriptors() bool {
	return len(p.eventFilterDescriptors) > 0
}

// Trace is the essential building block for controlling
// trace sessions and configuring event consumers. Such
// operations include starting, stopping, and flushing
// trace sessions, and opening the trace for processing
// and event consumption. Trace can be configured to
// operate a single ETW provider, or it can act as a
// container for multiple provider sessions.
type Trace interface {
	// Start registers and starts an event tracing session.
	// The session remains active until the session is stopped,
	// the machine is restarted, or an error occurs that would
	// interrupt the session.
	Start() error

	// Stop stops the event tracing session. From this point events
	// are not longer delivered to the session tracing buffers.
	Stop() error

	// Open opens an ETW trace processing handle for consuming events
	// from an ETW real-time trace. It specifies the callbacks the consumer
	// wants to use to receive the events or trace buffer statistics. The
	// first callback function that receives buffer-related
	// statistics for each buffer ETW flushes. ETW calls this callback after
	// it delivers all the events in the buffer. The second callback function
	// that ETW calls for each event in the buffer.
	Open(*Consumer, chan error) error

	// Close closes a trace processing session that was initiated
	// with the etw.OpenTrace function. This method should be called
	// after the respective session processing worker is started.
	Close() error

	// Process delivers events from the ETW trace processing sessions
	// to the consumer. This method attempts to deliver events in order
	// based on the event's timestamp - it tries to deliver events oldest
	// to newest. In certain cases, events might deliver events out of order.
	// The current thread is blocked upon calling this method, so be sure
	// to spawn a dedicated goroutine and use the provided error channel to
	// stream any errors.
	Process(chan error)

	// Flush causes an event tracing session to immediately deliver
	// buffered events for the specified session. By default, an event
	// tracing session will deliver events when the buffer is full,
	// the session's flusher timer expires, or the session is closed.
	Flush() error

	// CaptureState forces the provider to publish state information
	// such as rundown events.
	CaptureState() error

	// IsStarted indicates if the trace is started successfully.
	IsStarted() bool
	// IsRunning determines if the current trace is running.
	IsRunning() bool
	// Name returns the name of this tracing session.
	Name() string
	// Handle returns the trace control handle.
	Handle() etw.TraceHandle
}

// trace encaplusates the main building blocks and operations
// that all trace implementations rely on.
type trace struct {
	// guid is the globally unique identifier for the
	// provider for which the session is started. Only
	// relevant for global kernel providers.
	guid windows.GUID

	// name represents the unique tracing session name.
	name string

	// controlHandle is the session handle returned by the
	// etw.StartTrace function. This handle is
	// used for subsequent calls to other API
	// functions, but also to indicate if the
	// trace was started successfully. In this
	// case the trace handle is different from
	// zero.
	controlHandle etw.TraceHandle
	// traceHandle is the trace processing handle obtained
	// after the call to etw.OpenTrace function.
	// This handle is later handed over to the
	// trace processing function to consume events
	// from the real-time tracing session.
	traceHandle etw.TraceHandle
	// config represents global configuration store
	config *config.Config
	// consumer is the instance of the event consumer
	// responsible for processing events for the trace
	consumer *Consumer
	// errs receives event consumer errors
	errs chan error
}

func (t *trace) Name() string            { return t.name }
func (t *trace) Handle() etw.TraceHandle { return t.controlHandle }
func (t *trace) IsStarted() bool         { return t.controlHandle.IsValid() }
func (t *trace) IsRunning() bool         { return etw.ControlTrace(0, t.name, t.guid, etw.Query) == nil }

func (t *trace) Stop() error {
	return etw.StopTrace(t.name, t.guid)
}

func (t *trace) Flush() error {
	return etw.FlushTrace(t.name, t.guid)
}

func (t *trace) Open(consumer *Consumer, errs chan error) error {
	t.consumer = consumer
	t.errs = errs

	logfile := etw.NewEventTraceLogfile(t.name)
	logfile.SetEventCallback(windows.NewCallback(t.processEventCallback))
	logfile.SetBufferCallback(windows.NewCallback(t.bufferStatsCallback))
	logfile.SetModes(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)

	t.traceHandle = etw.OpenTrace(logfile)
	if !t.traceHandle.IsValid() {
		return fmt.Errorf("unable to open %s trace: %v", t.name, windows.GetLastError().Error())
	}
	return nil
}

// processEventCallback is the event callback function signature that is called each time
// a new event is available on the session buffer. It does the heavy lifting of parsing incoming
// ETW events from raw data buffers, building the state machine, and pushing events to the channel.
func (t *trace) processEventCallback(ev *etw.EventRecord) uintptr {
	if t.consumer == nil {
		panic("consumer is nil")
	}
	if err := t.consumer.ProcessEvent(ev); err != nil {
		t.errs <- err
		eventsFailed.Add(err.Error(), 1)
	}
	return callbackNext
}

// bufferStatsCallback is periodically triggered by ETW subsystem for the purpose of reporting
// buffer statistics, such as the number of buffers processed.
func (t *trace) bufferStatsCallback(logfile *etw.EventTraceLogfile) uintptr {
	buffersRead.Add(int64(logfile.BuffersRead))
	return callbackNext
}

func (t *trace) Process(ch chan error) {
	ch <- etw.ProcessTrace(t.traceHandle)
}

func (t *trace) Close() error {
	return etw.CloseTrace(t.traceHandle)
}

// KernelTrace is responsible for starting and processing
// events from the global NT Kernel Logger session.
type KernelTrace struct {
	trace
	// stackExtensions manages stack tracing enablement.
	// For each event present in the stack identifiers,
	// the StackWalk event is published by the provider.
	stackExtensions *StackExtensions
}

// UserTrace is responsible for starting a private tracing
// sessions with both kernel and user space providers. Every
// provider forming part of the tracing session needs to be
// enabled before events are consumed.
type UserTrace struct {
	trace
	// Providers is the list of providers to be run inside
	// the tracing session. For each provider, the GUID,
	// keywords and other parameters can be specified.
	Providers []ProviderInfo
}
type opts struct {
	keywords               uint64
	captureState           bool
	eventFilterDescriptors []etw.EventFilterDescriptor
}

// Option represents the option for the trace.
type Option func(o *opts)

// WithKeywords sets the bitmask of keywords that determine
// the categories of events for the provider to emit.
func WithKeywords(keywords uint64) Option {
	return func(o *opts) {
		o.keywords = keywords
	}
}

// WithCaptureState indicates that the provider should
// emit its state information.
func WithCaptureState() Option {
	return func(o *opts) {
		o.captureState = true
	}
}

// WithEventFilterDescriptors assigns filters to be passed
// to the provider's enable callback function.
func WithEventFilterDescriptors(descriptors ...etw.EventFilterDescriptor) Option {
	return func(o *opts) {
		o.eventFilterDescriptors = descriptors
	}
}

// NewKernelTrace creates a new NT Kernel Logger trace.
func NewKernelTrace(config *config.Config) *KernelTrace {
	t := &KernelTrace{trace: trace{guid: etw.KernelTraceControlGUID, name: etw.KernelLoggerSession, config: config}, stackExtensions: NewStackExtensions(config.EventSource)}

	t.stackExtensions.EnableProcessCallstack()
	t.stackExtensions.EnableRegistryCallstack()
	t.stackExtensions.EnableFileCallstack()
	t.stackExtensions.EnableMemoryCallstack()

	return t
}

// NewTrace creates a new trace that can host various ETW provider sessions.
// The providers to be run inside the session can be given in the last argument
// or added by the AddProvider method.
func NewUserTrace(name string, config *config.Config, providers ...ProviderInfo) *UserTrace {
	t := &UserTrace{trace: trace{name: name, config: config}, Providers: make([]ProviderInfo, 0)}
	t.Providers = providers
	return t
}

// AddProvider adds a new provider to the multi trace session
// with optional parameters that influence the provider.
func (t *UserTrace) AddProvider(guid windows.GUID, enableStacks bool, options ...Option) {
	var opts opts

	for _, opt := range options {
		opt(&opts)
	}

	t.Providers = append(
		t.Providers,
		ProviderInfo{GUID: guid, Keywords: opts.keywords, EnableStacks: enableStacks, CaptureState: opts.captureState, eventFilterDescriptors: opts.eventFilterDescriptors},
	)
}

// HasProviders determines if this trace contains providers.
func (t *UserTrace) HasProviders() bool { return len(t.Providers) > 0 }

func (t *KernelTrace) Start() error {
	if len(t.name) > maxLoggerNameSize {
		return fmt.Errorf("trace name [%s] is too long", t.name)
	}

	props := initEventTraceProps(t.config.EventSource)
	flags := enableFlagsDynamically(t.config.EventSource)

	props.EnableFlags = flags
	props.Wnode.GUID = t.guid

	log.Debugf("starting kernel trace with %q event flags", props.EnableFlags)

	var err error
	t.controlHandle, err = etw.StartTrace(
		t.name,
		props,
	)
	if err != nil {
		return err
	}
	if !t.controlHandle.IsValid() {
		return errs.ErrInvalidTrace
	}

	handle := t.controlHandle

	// when we call `TraceSetInformation` with event empty group mask reserved for the
	// flags that are bitvectored into `EventTraceProperties` structure's `EnableFlags` field,
	// it will trigger the arrival of rundown events including open file objects and
	// registry keys that are very valuable for us to construct the initial snapshot of
	// these system resources and let us build the state machine
	sysTraceFlags := make([]etw.EventTraceFlags, 8)
	if err := etw.SetTraceSystemFlags(handle, sysTraceFlags); err != nil {
		log.Warnf("unable to set empty system flags: %v", err)
		return nil
	}
	// enable stack enrichment
	if t.config.EventSource.StackEnrichment {
		if err := etw.EnableStackTracing(handle, t.stackExtensions.EventIds()); err != nil {
			return fmt.Errorf("fail to enable kernel callstack tracing: %v", err)
		}
	}
	// call again to enable all kernel events
	sysTraceFlags[0] = flags
	return etw.SetTraceSystemFlags(handle, sysTraceFlags)
}

func (*KernelTrace) CaptureState() error { return nil }

func (t *UserTrace) Start() error {
	if len(t.name) > maxLoggerNameSize {
		return fmt.Errorf("trace name [%s] is too long", t.name)
	}

	props := initEventTraceProps(t.config.EventSource)

	log.Debug("starting user trace session")

	var err error
	t.controlHandle, err = etw.StartTrace(
		t.name,
		props,
	)
	if err != nil {
		return err
	}
	if !t.controlHandle.IsValid() {
		return errs.ErrInvalidTrace
	}

	// For each provider in multi trace, the call to etw.EnableTrace is
	// needed to configure how an ETW provider publishes events to the
	// trace session.
	// For instance, if stack enrichment is enabled, it is necessary to
	// instruct the provider to emit stack addresses in the extended
	// data item section when writing events to the session buffers
	for _, provider := range t.Providers {
		switch {
		case provider.EnableStacks || provider.HasEventFilterDescriptors():
			opts := etw.EnableTraceOpts{
				WithStacktrace:         provider.EnableStacks,
				EventFilterDescriptors: provider.eventFilterDescriptors,
			}
			if err := etw.EnableTraceWithOpts(provider.GUID, t.controlHandle, provider.Keywords, opts); err != nil {
				return err
			}
		default:
			if err := etw.EnableTrace(provider.GUID, t.controlHandle, provider.Keywords); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t *UserTrace) CaptureState() error {
	for _, provider := range t.Providers {
		if !provider.CaptureState {
			continue
		}
		if err := etw.CaptureProviderState(provider.GUID, t.controlHandle); err != nil {
			return fmt.Errorf("unable to capture %s provider state: %v", provider.GUID, err)
		}
	}
	return nil
}

// initEventTraceProps builds the trace properties descriptor which
// influences the behaviour of event publishing to the trace session
// buffers.
func initEventTraceProps(c config.EventSourceConfig) etw.EventTraceProperties {
	bufferSize := min(c.BufferSize, maxBufferSize)

	// validate min/max buffers. The minimal
	// number of buffers is 2 per CPU logical core
	minBuffers := c.MinBuffers
	if minBuffers < uint32(runtime.NumCPU()*2) {
		minBuffers = uint32(runtime.NumCPU() * 2)
	}
	maxBuffers := c.MaxBuffers
	maxBuffersAllowed := minBuffers + 20
	if maxBuffers > maxBuffersAllowed {
		maxBuffers = maxBuffersAllowed
	}
	if minBuffers > maxBuffers {
		minBuffers = maxBuffers - 20
	}
	flushTimer := max(c.FlushTimer, time.Second)

	mode := uint32(etw.ProcessTraceModeRealtime)

	return etw.EventTraceProperties{
		Wnode: etw.WnodeHeader{
			BufferSize:    uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + maxTracePropsSize,
			Flags:         etw.WnodeTraceFlagGUID,
			ClientContext: 2, // System time: The system time provides a time stamp that tracks changes to the system’s clock
		},
		BufferSize:     bufferSize,
		LogFileMode:    mode,
		MinimumBuffers: minBuffers,
		MaximumBuffers: maxBuffers,
		FlushTimer:     uint32(flushTimer.Seconds()),
	}
}

// enableFlagsDynamically crafts the system logger event mask
// depending on the compiled rules result or the config state.
// System logger flags is a bitmask that indicates which kernel events
// are delivered to the consumer when system logger session is
// started. At minimum, process events are published to the trace
// session as they represent the foundation for building the state
// machine. Note these flags are relevant to system logger traces
// and initializing the EnableFlags field of the etw.EventTraceProperties
// structure for non-system logger providers will result in an error.
func enableFlagsDynamically(config config.EventSourceConfig) etw.EventTraceFlags {
	var flags etw.EventTraceFlags

	flags |= etw.Process

	if config.EnableThreadEvents {
		flags |= etw.Thread
	}
	if config.EnableModuleEvents {
		flags |= etw.Module
	}
	if config.EnableNetEvents {
		flags |= etw.NetTCPIP
	}
	if config.EnableRegistryEvents {
		flags |= etw.Registry
	}
	if config.EnableFileIOEvents {
		flags |= etw.DiskFileIO | etw.FileIO | etw.FileIOInit
	}
	if config.EnableVAMapEvents {
		flags |= etw.VaMap
	}
	if config.EnableMemEvents {
		flags |= etw.VirtualAlloc
	}
	if config.EnableRegistryEvents {
		flags |= etw.Registry
	}

	return flags
}
