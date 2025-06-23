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
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/source"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
	"time"
)

const (
	// callbackNext is the return callback value which indicates that callback execution should progress
	callbackNext = uintptr(1)

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

var (
	// eventsFailed counts the number of events that failed to process
	eventsFailed = expvar.NewMap("eventsource.events.failed")
	// eventsProcessed counts the number of total processed events
	eventsProcessed = expvar.NewInt("eventsource.events.processed")
	// eventsUnknown counts the number of published events which types are not present in the internal catalog
	eventsUnknown = expvar.NewInt("eventsource.events.unknown")
	// eventsExcluded counts the number of excluded events
	eventsExcluded = expvar.NewInt("eventsource.events.excluded")
	// buffersRead amount of buffers fetched from the ETW session
	buffersRead = expvar.NewInt("eventsource.buffers.read")
)

// EventSource is the core component responsible for
// starting ETW tracing sessions and setting up event
// consumers.
type EventSource struct {
	r         *config.RulesCompileResult
	traces    []*Trace
	consumers []*Consumer

	errs      chan error
	evts      chan *event.Event
	sequencer *event.Sequencer
	config    *config.Config
	stop      chan struct{}

	psnap ps.Snapshotter
	hsnap handle.Snapshotter

	filter    filter.Filter
	listeners []event.Listener

	isClosed bool
}

// NewEventSource creates the new ETW event source.
func NewEventSource(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
	compiler *config.RulesCompileResult,
) source.EventSource {
	evs := &EventSource{
		r:         compiler,
		traces:    make([]*Trace, 0),
		consumers: make([]*Consumer, 0),
		errs:      make(chan error, 1000),
		evts:      make(chan *event.Event, 500),
		sequencer: event.NewSequencer(),
		config:    config,
		stop:      make(chan struct{}),
		psnap:     psnap,
		hsnap:     hsnap,
		listeners: make([]event.Listener, 0),
	}
	return evs
}

// Open configures and starts traces and event consumers.
func (e *EventSource) Open(config *config.Config) error {
	// set up drop masks if the rule engine
	// is enabled. For any event not present
	// in the rule set, the drop mask instructs
	// to reject the event as soon as it is consumed
	// from the session buffer. Config value takes
	// precedence over rules compile result flag.
	// For example, if the CreateThread event is
	// used by the rules, but thread events are
	// disabled in the config, then thread events
	// are not captured
	if e.r != nil {
		config.EventSource.EnableThreadEvents = config.EventSource.EnableThreadEvents && e.r.HasThreadEvents
		config.EventSource.EnableImageEvents = config.EventSource.EnableImageEvents && e.r.HasImageEvents
		config.EventSource.EnableNetEvents = config.EventSource.EnableNetEvents && e.r.HasNetworkEvents
		config.EventSource.EnableRegistryEvents = config.EventSource.EnableRegistryEvents && (e.r.HasRegistryEvents || (config.Yara.Enabled && !config.Yara.SkipRegistry))
		config.EventSource.EnableFileIOEvents = config.EventSource.EnableFileIOEvents && (e.r.HasFileEvents || (config.Yara.Enabled && !config.Yara.SkipFiles))
		config.EventSource.EnableVAMapEvents = config.EventSource.EnableVAMapEvents && (e.r.HasVAMapEvents || (config.Yara.Enabled && !config.Yara.SkipMmaps))
		config.EventSource.EnableMemEvents = config.EventSource.EnableMemEvents && (e.r.HasMemEvents || (config.Yara.Enabled && !config.Yara.SkipAllocs))
		config.EventSource.EnableDNSEvents = config.EventSource.EnableDNSEvents && e.r.HasDNSEvents
		config.EventSource.EnableAuditAPIEvents = config.EventSource.EnableAuditAPIEvents && e.r.HasAuditAPIEvents
		config.EventSource.EnableThreadpoolEvents = config.EventSource.EnableThreadpoolEvents && e.r.HasThreadpoolEvents
		for _, typ := range event.All() {
			if typ == event.CreateProcess || typ == event.TerminateProcess ||
				typ == event.LoadImage || typ == event.UnloadImage {
				// always allow fundamental events
				continue
			}

			// allow events required for memory/file scanning
			if typ == event.MapViewFile && config.Yara.Enabled && !config.Yara.SkipMmaps {
				continue
			}
			if typ == event.VirtualAlloc && config.Yara.Enabled && !config.Yara.SkipAllocs {
				continue
			}
			if typ == event.CreateFile && config.Yara.Enabled && !config.Yara.SkipFiles {
				continue
			}
			if typ == event.RegSetValue && config.Yara.Enabled && !config.Yara.SkipRegistry {
				continue
			}

			if !e.r.ContainsEvent(typ) {
				config.EventSource.SetDropMask(typ)
			}
		}
	}

	// security telemetry trace hosts all ETW providers but NT Kernel Logger
	trace := NewTrace(etw.SecurityTelemetrySession, config)

	// Windows Kernel Process session permits enriching event state with
	// additional attributes and guaranteeing that any event published by
	// the security telemetry session doesn't miss its respective process
	// from the snapshotter
	trace.AddProvider(etw.WindowsKernelProcessGUID, false, WithKeywords(etw.ProcessKeyword|etw.ImageKeyword), WithCaptureState())

	if config.EventSource.EnableDNSEvents {
		trace.AddProvider(etw.DNSClientGUID, false)
	}

	if config.EventSource.EnableAuditAPIEvents {
		trace.AddProvider(etw.KernelAuditAPICallsGUID, config.EventSource.StackEnrichment)
	}

	if config.EventSource.EnableThreadpoolEvents {
		// thread pool provider must be configured with
		// stack extensions to activate stack walks events
		var stackexts *StackExtensions
		if e.config.EventSource.StackEnrichment {
			stackexts = NewStackExtensions(config.EventSource)
			stackexts.EnableThreadpoolCallstack()
		}
		trace.AddProvider(etw.ThreadpoolGUID, config.EventSource.StackEnrichment, WithStackExts(stackexts))
	}

	// add security telemetry trace
	e.addTrace(trace)
	// add the core NT Kernel Logger trace
	e.addTrace(NewKernelTrace(config))

	for _, t := range e.traces {
		err := t.Start()
		switch err {
		case errs.ErrTraceAlreadyRunning:
			log.Debugf("%s trace is already running. Trying to restart...", t.Name)
			if err := t.Stop(); err != nil {
				return err
			}
			time.Sleep(time.Millisecond * 100)
			if err := t.Start(); err != nil {
				return multierror.Wrap(errs.ErrRestartTrace, err)
			}
		case errs.ErrTraceNoSysResources:
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

		// Init consumer and open the trace for processing
		consumer := NewConsumer(e.psnap, e.hsnap, config, e.sequencer, e.evts)
		consumer.SetFilter(e.filter)

		// Attach event listeners
		for _, lis := range e.listeners {
			consumer.q.RegisterListener(lis)
		}
		e.consumers = append(e.consumers, consumer)

		// Open the trace and assign a consumer
		err = t.Open(consumer, e.errs)
		if err != nil {
			return fmt.Errorf("unable to open %s trace: %v", t.Name, err)
		}
		log.Infof("starting [%s] trace processing", t.Name)

		// Instruct the provider to emit state information
		err = t.CaptureState()
		if err != nil {
			log.Warn(err)
		}

		// Start event processing loop
		errch := make(chan error)
		go t.Process(errch)

		go func(trace *Trace) {
			select {
			case <-e.stop:
				return
			case err := <-errch:
				log.Infof("stopping [%s] trace processing", trace.Name)
				if err != nil && !errors.Is(err, errs.ErrTraceCancelled) {
					e.errs <- fmt.Errorf("unable to process %s trace: %v", trace.Name, err)
				}
			}
		}(t)
	}

	return nil
}

// Close shutdowns all tracing sessions orderly. Firstly,
// the buffers are flushed. Then, the trace is closed to
// signal the event callback to stop consuming more events.
// Finally, the trace is stopped along with all event consumers.
func (e *EventSource) Close() error {
	if e.isClosed {
		return nil
	}

	for _, consumer := range e.consumers {
		if err := consumer.Close(); err != nil {
			log.Warnf("couldn't close consumer: %v", err)
		}
	}

	for _, trace := range e.traces {
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

	close(e.stop)

	e.isClosed = true

	return e.sequencer.Shutdown()
}

// Errors returns the channel where errors are published.
func (e *EventSource) Errors() <-chan error {
	return e.errs
}

// Events returns the buffered event channel.
func (e *EventSource) Events() <-chan *event.Event {
	return e.evts
}

// SetFilter assigns the filter to each consumer. The filter is applied
// to every event captured by the consumer. If the filter expression
// matches, then the consumer enqueues the event to the output queue.
func (e *EventSource) SetFilter(f filter.Filter) {
	e.filter = f
}

// RegisterEventListener registers a new event listener for each consumer queue.
// The event is pushed to the output queue if at least one of the listeners allows.
func (e *EventSource) RegisterEventListener(lis event.Listener) {
	e.listeners = append(e.listeners, lis)
}

func (e *EventSource) addTrace(trace *Trace) {
	e.traces = append(e.traces, trace)
}
