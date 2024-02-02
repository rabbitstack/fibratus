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

package kstream

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"golang.org/x/sys/windows"
	"runtime"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	// maxBufferSize specifies the maximum buffer size for event tracing session buffer
	maxBufferSize = 1024
	// etwMaxLoggersPath is the registry subkey that contains ETW logger preferences
	etwMaxLoggersPath = `SYSTEM\CurrentControlSet\Control\WMI`
	// etwMaxLoggersValue is the registry value that dictates the maximum number of loggers. Default value is 64 on most systems
	etwMaxLoggersValue = "EtwMaxLoggers"
	maxLoggerNameSize  = 128
	maxLogfileNameSize = 1024
	// maxTracePropsSize must make room for logger name and log file name
	maxTracePropsSize = 2 * (maxLoggerNameSize + maxLogfileNameSize)
)

// StackEventIdentifiers is the type alias for stack events identifiers
type StackEventIdentifiers []etw.ClassicEventID

// Add enables stack tracing for the specified event type.
func (s *StackEventIdentifiers) Add(ktype ktypes.Ktype) {
	*s = append(*s, etw.NewClassicEventID(ktype.GUID(), ktype.HookID()))
}

// AddWith enable stack tracing for the specified provider GUID and event hook identifier.
func (s *StackEventIdentifiers) AddWith(guid windows.GUID, hookID uint16) {
	*s = append(*s, etw.NewClassicEventID(guid, hookID))
}

// initEventTraceProps builds the trace properties descriptor which
// influences the behaviour of event publishing to the trace session
// buffers.
func initEventTraceProps(c config.KstreamConfig) etw.EventTraceProperties {
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
	return etw.EventTraceProperties{
		Wnode: etw.WnodeHeader{
			BufferSize:    uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + maxTracePropsSize,
			Flags:         etw.WnodeTraceFlagGUID,
			ClientContext: 1, // QPC clock resolution
		},
		BufferSize:     bufferSize,
		LogFileMode:    etw.ProcessTraceModeRealtime,
		MinimumBuffers: minBuffers,
		MaximumBuffers: maxBuffers,
		FlushTimer:     uint32(flushTimer.Seconds()),
	}
}

// Trace is the essential building block for controlling
// trace sessions and configuring event consumers. Such
// operations include starting, stopping, and flushing
// trace sessions, and opening the trace for processing
// and event consumption.
type Trace struct {
	// Name represents the unique tracing session name.
	Name string
	// GUID is the globally unique identifier for the
	// ETW provider.
	GUID windows.GUID
	// Keywords is the bitmask of keywords that determine
	// the categories of events for the provider to emit.
	// The provider typically writes an event if the event's
	// keyword bits match any of the bits set in this value
	// or if the event has no keyword bits set. Only relevant
	// for providers that are enabled via etw.EnableProvider
	// API.
	Keywords uint64

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
}

// NewTrace creates a new trace with specified name, provider GUID, and keywords.
func NewTrace(name string, guid windows.GUID, keywords uint64) *Trace {
	return &Trace{Name: name, GUID: guid, Keywords: keywords}
}

// Start registers and starts an event tracing session.
// The session remains active until the session is stopped,
// the machine is restarted, or an error occurs that would
// interrupt the session.
func (t *Trace) Start(config config.KstreamConfig) error {
	if len(t.Name) > maxLoggerNameSize {
		return fmt.Errorf("trace name [%s] is too long", t.Name)
	}
	props := initEventTraceProps(config)
	flags, ids := t.enableFlagsDynamically(config)
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
		return kerrors.ErrInvalidTrace
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
		// when we call the`TraceSetInformation` with event empty group mask reserved for the
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
		if config.EnableHandleKevents {
			sysTraceFlags[4] = etw.Handle
		}
		// enable stack enrichment
		if config.StackEnrichment {
			if err := etw.EnableStackTracing(handle, ids); err != nil {
				return fmt.Errorf("fail to enable kernel callstack tracing: %v", err)
			}
		}
		// call again to enable all kernel events. Just to recap. The first call to
		// `TraceSetInformation` with empty group masks activates rundown events,
		// while this second call enables the rest of the kernel events specified in flags.
		return etw.SetTraceSystemFlags(handle, sysTraceFlags)
	}
	// if we're starting a trace for non-system logger, the call
	// to etw.EnableTrace is needed to configure how an ETW provider
	// publishes events to the trace session. For instance, if stack
	// enrichment is enabled, it is necessary to instruct the provider
	// to emit stack addresses in the extended data item section when
	// writing events to the session buffers
	if config.StackEnrichment {
		return etw.EnableTraceWithOpts(t.GUID, t.startHandle, t.Keywords, etw.EnableTraceOpts{WithStacktrace: true})
	}
	return etw.EnableTrace(t.GUID, t.startHandle, t.Keywords)
}

// IsStarted indicates if the trace is started successfully.
func (t *Trace) IsStarted() bool { return t.startHandle.IsValid() }

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
// first parameter is the callback function that receives buffer-related
// statistics for each buffer ETW flushes. ETW calls this callback after
// it delivers all the events in the buffer. The second parameter is the
// callback function that ETW calls for each event in the buffer.
func (t *Trace) Open(bufferFn, eventFn EventCallback) error {
	logfile := etw.NewEventTraceLogfile(t.Name)
	logfile.SetEventCallback(windows.NewCallback(eventFn))
	logfile.SetBufferCallback(windows.NewCallback(bufferFn))
	logfile.SetModes(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)

	t.openHandle = etw.OpenTrace(logfile)
	if !t.openHandle.IsValid() {
		return fmt.Errorf("unable to open %s trace: %v", t.Name, windows.GetLastError().Error())
	}
	return nil
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

// IsKernelTrace determines if this is the system logger trace.
func (t *Trace) IsKernelTrace() bool { return t.GUID == etw.KernelTraceControlGUID }

// enableFlagsDynamically crafts the system logger event mask
// and call stack event identifiers conditionally, depending on
// the compiled rules result or the config state.
// System logger flags is a bitmask that indicates which kernel events
// are delivered to the consumer when system logger session is
// started. At minimum, process events are published to the trace
// session as they represent the foundation for building the state
// machine. Note these flags are relevant to system logger traces
// and initializing the EnableFlags field of the etw.EventTraceProperties
// structure for non-system logger providers will result in an error.
func (t *Trace) enableFlagsDynamically(config config.KstreamConfig) (etw.EventTraceFlags, []etw.ClassicEventID) {
	if !t.IsKernelTrace() {
		return 0, nil
	}

	var flags etw.EventTraceFlags
	ids := make(StackEventIdentifiers, 0)

	flags |= etw.Process
	ids.Add(ktypes.CreateProcess)

	if config.EnableThreadKevents {
		flags |= etw.Thread
		if !config.TestDropMask(ktypes.CreateThread) {
			ids.Add(ktypes.CreateThread)
		}
		if !config.TestDropMask(ktypes.TerminateThread) {
			ids.Add(ktypes.TerminateThread)
		}
	}
	if config.EnableImageKevents {
		flags |= etw.ImageLoad
		if !config.TestDropMask(ktypes.LoadImage) {
			ids.AddWith(ktypes.ProcessEventGUID, ktypes.LoadImage.HookID())
		}
	}
	if config.EnableNetKevents {
		flags |= etw.NetTCPIP
	}
	if config.EnableRegistryKevents {
		flags |= etw.Registry
		if !config.TestDropMask(ktypes.RegCreateKey) {
			ids.Add(ktypes.RegCreateKey)
		}
		if !config.TestDropMask(ktypes.RegDeleteKey) {
			ids.Add(ktypes.RegDeleteKey)
		}
		if !config.TestDropMask(ktypes.RegSetValue) {
			ids.Add(ktypes.RegSetValue)
		}
		if !config.TestDropMask(ktypes.RegDeleteValue) {
			ids.Add(ktypes.RegDeleteValue)
		}
	}
	if config.EnableFileIOKevents {
		flags |= etw.DiskFileIO | etw.FileIO | etw.FileIOInit
		if !config.TestDropMask(ktypes.CreateFile) {
			ids.Add(ktypes.CreateFile)
		}
		if !config.TestDropMask(ktypes.DeleteFile) {
			ids.Add(ktypes.DeleteFile)
		}
		if !config.TestDropMask(ktypes.RenameFile) {
			ids.Add(ktypes.RenameFile)
		}
	}
	if config.EnableVAMapKevents {
		flags |= etw.VaMap
	}
	if config.EnableMemKevents {
		flags |= etw.VirtualAlloc
	}

	return flags, ids
}

// Controller is responsible for managing the life cycle of the tracing sessions.
// More specifically, the following sessions are governed by the trace controller:
//
// NT System Logger: publishes core system events. Mandatory and always started
// Kernel Audit API Calls Logger: provides process/thread object events. Optional
// DNS Client Logger: publishes DNS queries/responses. Optional
type Controller struct {
	traces []*Trace
	config *config.Config
}

func (c *Controller) addTrace(name string, guid windows.GUID) {
	c.traces = append(c.traces, NewTrace(name, guid, 0x0))
}

// NewController spins up a new instance of the trace controller.
// The traces are populated depending on what the config state
// dictates unless the rule engine is enabled. In this case, the
// decision-maker is the rules compile result which drives the
// enablement of providers and controls bitmask setup.
func NewController(c *config.Config, r *config.RulesCompileResult) *Controller {
	controller := &Controller{
		config: c,
		traces: make([]*Trace, 0),
	}

	controller.addTrace(etw.KernelLoggerSession, etw.KernelTraceControlGUID)

	// dynamically enable event providers
	// and set up drop masks if the rule
	// engine is enabled. For any event
	// not present in the rule set, the
	// drop mask instructs to reject the
	// event as soon as it is consumed
	// from the session buffer
	if r != nil {
		c.Kstream.EnableThreadKevents = r.HasThreadEvents
		c.Kstream.EnableImageKevents = r.HasFileEvents
		c.Kstream.EnableNetKevents = r.HasNetworkEvents
		c.Kstream.EnableRegistryKevents = r.HasRegistryEvents
		c.Kstream.EnableFileIOKevents = r.HasFileEvents
		c.Kstream.EnableVAMapKevents = r.HasVAMapEvents
		c.Kstream.EnableMemKevents = r.HasMemEvents
		for _, ktype := range ktypes.All() {
			if ktype == ktypes.CreateProcess || ktype == ktypes.TerminateProcess {
				continue
			}
			if !r.ContainsEvent(ktype) {
				c.Kstream.SetDropMask(ktype)
			}
		}
		if r.HasDNSEvents {
			controller.addTrace(etw.DNSClientSession, etw.DNSClientGUID)
		}
		if r.HasAuditAPIEvents {
			controller.addTrace(etw.KernelAuditAPICallsSession, etw.KernelAuditAPICallsGUID)
		}
		return controller
	}
	if c.Kstream.EnableDNSEvents {
		controller.addTrace(etw.DNSClientSession, etw.DNSClientGUID)
	}
	if c.Kstream.EnableAuditAPIEvents {
		controller.addTrace(etw.KernelAuditAPICallsSession, etw.KernelAuditAPICallsGUID)
	}
	return controller
}

// Start starts configured tracing sessions. User has the ability to disable
// a specific subset of collected kernel events, even though by default most
// events are forwarded from the system logger provider.
func (c *Controller) Start() error {
	for _, trace := range c.traces {
		err := trace.Start(c.config.Kstream)
		switch err {
		case kerrors.ErrTraceAlreadyRunning:
			log.Debugf("%s trace is already running. Trying to restart...", trace.Name)
			if err := trace.Stop(); err != nil {
				return err
			}
			time.Sleep(time.Millisecond * 100)
			if err := trace.Start(c.config.Kstream); err != nil {
				return multierror.Wrap(kerrors.ErrRestartTrace, err)
			}
		case kerrors.ErrTraceNoSysResources:
			// get the number of maximum allowed loggers from registry
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, etwMaxLoggersPath, registry.QUERY_VALUE)
			if err != nil {
				return err
			}
			v, _, err := key.GetIntegerValue(etwMaxLoggersValue)
			if err != nil {
				_ = key.Close()
				return err
			}
			_ = key.Close()
			return fmt.Errorf(`the limit for logging sessions on your system is %d. Please consider increasing this number `+
				`by editing HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers key in registry. `+
				`Permissible values are 32 through 256 inclusive, and a reboot is required for any change to take effect`, v)
		default:
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Close stops currently running tracing sessions.
func (c *Controller) Close() error {
	for _, trace := range c.traces {
		if !trace.IsStarted() {
			continue
		}
		if err := trace.Flush(); err != nil {
			log.Warnf("couldn't flush trace session for [%s]: %v", trace.Name, err)
		}
		time.Sleep(time.Millisecond * 150)
		if err := trace.Close(); err != nil {
			log.Warnf("couldn't close trace session for [%s]: %v", trace.Name, err)
		}
		time.Sleep(time.Millisecond * 250)
		if err := trace.Stop(); err != nil {
			log.Warnf("couldn't stop trace session for [%s]: %v", trace.Name, err)
		}
	}
	return nil
}

// Traces returns all configured tracing sessions.
func (c *Controller) Traces() []*Trace {
	return c.traces
}
