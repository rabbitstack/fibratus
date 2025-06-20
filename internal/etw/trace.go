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
	"github.com/rabbitstack/fibratus/pkg/config"
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"runtime"
	"time"
	"unsafe"
)

// initEventTraceProps builds the trace properties descriptor which
// influences the behaviour of event publishing to the trace session
// buffers.
func initEventTraceProps(c config.EventSourceConfig) etw.EventTraceProperties {
	bufferSize := c.BufferSize
	if bufferSize > maxBufferSize {
		bufferSize = maxBufferSize
	}
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
	flushTimer := c.FlushTimer
	if flushTimer < time.Second {
		flushTimer = time.Second
	}

	mode := uint32(etw.ProcessTraceModeRealtime)

	return etw.EventTraceProperties{
		Wnode: etw.WnodeHeader{
			BufferSize:    uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + maxTracePropsSize,
			Flags:         etw.WnodeTraceFlagGUID,
			ClientContext: 1, // QPC clock resolution
		},
		BufferSize:     bufferSize,
		LogFileMode:    mode,
		MinimumBuffers: minBuffers,
		MaximumBuffers: maxBuffers,
		FlushTimer:     uint32(flushTimer.Seconds()),
	}
}

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
	// stackExtensions manager stack tracing enablement.
	// For each event present in the stack identifiers,
	// the StackWalk event is published by the provider.
	stackExtensions *StackExtensions
}

func (p *ProviderInfo) HasStackExtensions() bool {
	return p.stackExtensions != nil && !p.stackExtensions.Empty()
}

// Trace is the essential building block for controlling
// trace sessions and configuring event consumers. Such
// operations include starting, stopping, and flushing
// trace sessions, and opening the trace for processing
// and event consumption. Trace can be configured to
// operate a single ETW provider, or it can act as a
// container for multiple provider sessions.
type Trace struct {
	// Name represents the unique tracing session name.
	Name string
	// GUID is the globally unique identifier for the
	// ETW provider for which the session is started.
	GUID windows.GUID

	// Providers is the list of providers to be run inside
	// the tracing session. For each provider, the GUID,
	// keywords and other parameters can be specified.
	Providers []ProviderInfo

	// stackExtensions manages stack tracing enablement.
	// For each event present in the stack identifiers,
	// the StackWalk event is published by the provider.
	stackExtensions *StackExtensions

	// startHandle is the session handle returned by the
	// etw.StartTrace function. This handle is
	// used for subsequent calls to other API
	// functions, but also to indicate if the
	// trace was started successfully. In this
	// case the trace handle is different from
	// zero.
	startHandle etw.TraceHandle
	// openHandle is the trace processing handle obtained
	// after the call to etw.OpenTrace function.
	// This handle is later handed over to the
	// trace processing function to consume events
	// from the real-time tracing session.
	openHandle etw.TraceHandle
	// config represents global configuration store
	config *config.Config
	// consumer is the instance of the event consumer
	// responsible for processing events for the trace
	consumer *Consumer
	// errs receives event consumer errors
	errs chan error
}

type opts struct {
	stackexts    *StackExtensions
	keywords     uint64
	captureState bool
}

// Option represents the option for the trace.
type Option func(o *opts)

// WithStackExts sets the stack extensions.
func WithStackExts(stackexts *StackExtensions) Option {
	return func(o *opts) {
		o.stackexts = stackexts
	}
}

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

// NewKernelTrace creates a new NT Kernel Logger trace.
func NewKernelTrace(config *config.Config) *Trace {
	t := &Trace{Name: etw.KernelLoggerSession, GUID: etw.KernelTraceControlGUID, stackExtensions: NewStackExtensions(config.EventSource), config: config}
	t.enableCallstacks()
	return t
}

// NewTrace creates a new trace that can host various ETW provider sessions.
// The providers to be run inside the session can be given in the last argument
// or added by the AddProvider method.
func NewTrace(name string, config *config.Config, providers ...ProviderInfo) *Trace {
	t := &Trace{Name: name, config: config, Providers: make([]ProviderInfo, 0)}
	t.Providers = providers
	return t
}

// AddProvider adds a new provider to the multi trace session
// with optional parameters that influence the provider.
func (t *Trace) AddProvider(guid windows.GUID, enableStacks bool, options ...Option) {
	var opts opts

	for _, opt := range options {
		opt(&opts)
	}

	t.Providers = append(
		t.Providers,
		ProviderInfo{GUID: guid, Keywords: opts.keywords, EnableStacks: enableStacks, CaptureState: opts.captureState, stackExtensions: opts.stackexts},
	)
}

// HasProviders determines if this trace contains providers.
func (t *Trace) HasProviders() bool { return len(t.Providers) > 0 }

// IsGUIDEmpty determines if the provider GUID is empty.
func (t *Trace) IsGUIDEmpty() bool {
	return t.GUID.Data1 == 0 &&
		t.GUID.Data2 == 0 &&
		t.GUID.Data3 == 0 &&
		t.GUID.Data4 == [8]byte{}
}

func (t *Trace) enableCallstacks() {
	if t.IsKernelTrace() {
		t.stackExtensions.EnableProcessCallstack()

		t.stackExtensions.EnableRegistryCallstack()

		t.stackExtensions.EnableFileCallstack()

		t.stackExtensions.EnableMemoryCallstack()
	}
}

// Start registers and starts an event tracing session.
// The session remains active until the session is stopped,
// the machine is restarted, or an error occurs that would
// interrupt the session.
func (t *Trace) Start() error {
	if len(t.Name) > maxLoggerNameSize {
		return fmt.Errorf("trace name [%s] is too long", t.Name)
	}

	if !t.IsGUIDEmpty() && t.HasProviders() {
		return fmt.Errorf("%s trace has the root GUID set but providers are not empty", t.Name)
	}

	cfg := t.config.EventSource
	props := initEventTraceProps(cfg)
	flags := t.enableFlagsDynamically(cfg)

	if t.IsKernelTrace() {
		props.EnableFlags = flags
		props.Wnode.GUID = t.GUID
		log.Debugf("starting kernel trace with %q event flags", props.EnableFlags)
	}

	log.Debugf("starting trace [%s]", t.Name)

	var err error
	t.startHandle, err = etw.StartTrace(
		t.Name,
		props,
	)
	if err != nil {
		return err
	}
	if !t.startHandle.IsValid() {
		return errs.ErrInvalidTrace
	}

	if t.IsKernelTrace() {
		handle := t.startHandle
		// poorly documented ETW feature that allows for enabling an extended set of
		// kernel event tracing flags. According to the MSDN documentation, aside from
		// invoking `EventTraceProperties` function to enable object manager tracking
		// the `EventTraceProperties` structure's `EnableFlags` member needs to be set
		// to PERF_OB_HANDLE (0x80000040). This actually results in an erroneous trace start.
		// The documentation neither specifies how the function should be called, group mask
		// array with its 4th element set to 0x80000040.
		sysTraceFlags := make([]etw.EventTraceFlags, 8)
		// when we call `TraceSetInformation` with event empty group mask reserved for the
		// flags that are bitvectored into `EventTraceProperties` structure's `EnableFlags` field,
		// it will trigger the arrival of rundown events including open file objects and
		// registry keys that are very valuable for us to construct the initial snapshot of
		// these system resources and let us build the state machine
		if err := etw.SetTraceSystemFlags(handle, sysTraceFlags); err != nil {
			log.Warnf("unable to set empty system flags: %v", err)
			return nil
		}

		sysTraceFlags[0] = flags

		// enable object manager tracking
		if cfg.EnableHandleEvents {
			sysTraceFlags[4] = etw.Handle
		}
		// enable stack enrichment
		if cfg.StackEnrichment {
			if err := etw.EnableStackTracing(handle, t.stackExtensions.EventIds()); err != nil {
				return fmt.Errorf("fail to enable kernel callstack tracing: %v", err)
			}
		}
		// call again to enable all kernel events. Just to recap. The first call to
		// `TraceSetInformation` with empty group masks activates rundown events,
		// while this second call enables the rest of the kernel events specified in flags.
		return etw.SetTraceSystemFlags(handle, sysTraceFlags)
	}

	// For each provider in multi trace, the call to etw.EnableTrace is
	// needed to configure how an ETW provider publishes events to the
	// trace session.
	// For instance, if stack enrichment is enabled, it is necessary to
	// instruct the provider to emit stack addresses in the extended
	// data item section when writing events to the session buffers
	for _, provider := range t.Providers {
		switch {
		case provider.EnableStacks && provider.HasStackExtensions():
			if err := etw.EnableStackTracing(t.startHandle, provider.stackExtensions.EventIds()); err != nil {
				return fmt.Errorf("fail to enable provider callstack tracing: %v", err)
			}
			if err := etw.EnableTrace(provider.GUID, t.startHandle, provider.Keywords); err != nil {
				return err
			}
		case provider.EnableStacks:
			opts := etw.EnableTraceOpts{WithStacktrace: true}
			if err := etw.EnableTraceWithOpts(provider.GUID, t.startHandle, provider.Keywords, opts); err != nil {
				return err
			}
		default:
			if err := etw.EnableTrace(provider.GUID, t.startHandle, provider.Keywords); err != nil {
				return err
			}
		}
	}

	return nil
}

// IsStarted indicates if the trace is started successfully.
func (t *Trace) IsStarted() bool { return t.startHandle.IsValid() }

// IsRunning determines if the current trace is running.
func (t *Trace) IsRunning() bool { return etw.ControlTrace(0, t.Name, t.GUID, etw.Query) == nil }

// Handle returns the trace handle returned by etw.StartTrace function.
func (t *Trace) Handle() etw.TraceHandle {
	return t.startHandle
}

// Stop stops the event tracing session.
func (t *Trace) Stop() error {
	return etw.StopTrace(t.Name, t.GUID)
}

// Flush causes an event tracing session to immediately deliver
// buffered events for the specified session. By default, an event
// tracing session will deliver events when the buffer is full,
// the session's flusher timer expires, or the session is closed.
func (t *Trace) Flush() error {
	return etw.FlushTrace(t.Name, t.GUID)
}

// Open opens an ETW trace processing handle for consuming events
// from an ETW real-time trace. It specifies the callbacks the consumer
// wants to use to receive the events or trace buffer statistics. The
// first callback function that receives buffer-related
// statistics for each buffer ETW flushes. ETW calls this callback after
// it delivers all the events in the buffer. The second callback function
// that ETW calls for each event in the buffer.
func (t *Trace) Open(consumer *Consumer, errs chan error) error {
	t.consumer = consumer
	t.errs = errs
	logfile := etw.NewEventTraceLogfile(t.Name)
	logfile.SetEventCallback(windows.NewCallback(t.processEventCallback))
	logfile.SetBufferCallback(windows.NewCallback(t.bufferStatsCallback))
	logfile.SetModes(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)

	t.openHandle = etw.OpenTrace(logfile)
	if !t.openHandle.IsValid() {
		return fmt.Errorf("unable to open %s trace: %v", t.Name, windows.GetLastError().Error())
	}
	return nil
}

// processEventCallback is the event callback function signature that is called each time
// a new event is available on the session buffer. It does the heavy lifting of parsing incoming
// ETW events from raw data buffers, building the state machine, and pushing events to the channel.
func (t *Trace) processEventCallback(ev *etw.EventRecord) uintptr {
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
func (t *Trace) bufferStatsCallback(logfile *etw.EventTraceLogfile) uintptr {
	buffersRead.Add(int64(logfile.BuffersRead))
	return callbackNext
}

// Process delivers events from the ETW trace processing sessions
// to the consumer. This method attempts to deliver events in order
// based on the event's timestamp - it tries to deliver events oldest
// to newest. In certain cases, events might deliver events out of order.
// The current thread is blocked upon calling this method, so be sure
// to spawn a dedicated goroutine and use the provided error channel to
// stream any errors.
func (t *Trace) Process(ch chan error) {
	ch <- etw.ProcessTrace(t.openHandle)
}

// Close closes a trace processing session that was initiated
// with the etw.OpenTrace function. This method should be called
// after the respective session processing worker is started.
func (t *Trace) Close() error {
	return etw.CloseTrace(t.openHandle)
}

// CaptureState forces the provider to publish state
// information such as rundown events.
func (t *Trace) CaptureState() error {
	for _, provider := range t.Providers {
		if !provider.CaptureState {
			continue
		}
		if err := etw.CaptureProviderState(provider.GUID, t.startHandle); err != nil {
			return fmt.Errorf("unable to capture %s provider state: %v", provider.GUID, err)
		}
	}
	return nil
}

// IsKernelTrace determines if this is the system logger trace.
func (t *Trace) IsKernelTrace() bool { return t.GUID == etw.KernelTraceControlGUID }

// enableFlagsDynamically crafts the system logger event mask
// depending on the compiled rules result or the config state.
// System logger flags is a bitmask that indicates which kernel events
// are delivered to the consumer when system logger session is
// started. At minimum, process events are published to the trace
// session as they represent the foundation for building the state
// machine. Note these flags are relevant to system logger traces
// and initializing the EnableFlags field of the etw.EventTraceProperties
// structure for non-system logger providers will result in an error.
func (t *Trace) enableFlagsDynamically(config config.EventSourceConfig) etw.EventTraceFlags {
	var flags etw.EventTraceFlags

	if !t.IsKernelTrace() {
		return flags
	}

	flags |= etw.Process

	if config.EnableThreadEvents {
		flags |= etw.Thread
	}
	if config.EnableImageEvents {
		flags |= etw.ImageLoad
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
