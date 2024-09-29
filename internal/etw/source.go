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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ksource"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
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
	// failedKevents counts the number of kevents that failed to process
	failedKevents = expvar.NewMap("kstream.kevents.failures")
	// keventsProcessed counts the number of total processed events
	keventsProcessed = expvar.NewInt("kstream.kevents.processed")
	// keventsDropped counts the number of overall dropped events
	keventsDropped = expvar.NewInt("kstream.kevents.dropped")
	// keventsUnknown counts the number of published events which types are not present in the internal catalog
	keventsUnknown = expvar.NewInt("kstream.kevents.unknown")

	// excludedKevents counts the number of excluded events
	excludedKevents = expvar.NewInt("kstream.excluded.kevents")

	// buffersRead amount of buffers fetched from the ETW session
	buffersRead = expvar.NewInt("kstream.kbuffers.read")
)

// SupportsSystemProviders determines if the support for granular
// system providers in present.
func SupportsSystemProviders() bool {
	maj, _, patch := windows.RtlGetNtVersionNumbers()
	if maj > 10 {
		return true
	}
	return maj >= 10 && patch >= 20348
}

// EventSource is the core component responsible for
// starting ETW tracing sessions and setting up event
// consumers.
type EventSource struct {
	r         *config.RulesCompileResult
	traces    []*Trace
	consumers []*Consumer

	errs      chan error
	evts      chan *kevent.Kevent
	sequencer *kevent.Sequencer
	config    *config.Config
	stop      chan struct{}

	psnap ps.Snapshotter
	hsnap handle.Snapshotter

	filter    filter.Filter
	listeners []kevent.Listener
}

// NewEventSource creates the new ETW event source.
func NewEventSource(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
	compiler *config.RulesCompileResult,
) ksource.EventSource {
	evs := &EventSource{
		r:         compiler,
		traces:    make([]*Trace, 0),
		consumers: make([]*Consumer, 0),
		errs:      make(chan error, 1000),
		evts:      make(chan *kevent.Kevent, 500),
		sequencer: kevent.NewSequencer(),
		config:    config,
		stop:      make(chan struct{}),
		psnap:     psnap,
		hsnap:     hsnap,
		listeners: make([]kevent.Listener, 0),
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
		config.Kstream.EnableThreadKevents = config.Kstream.EnableThreadKevents && e.r.HasThreadEvents
		config.Kstream.EnableImageKevents = config.Kstream.EnableImageKevents && e.r.HasImageEvents
		config.Kstream.EnableNetKevents = config.Kstream.EnableNetKevents && e.r.HasNetworkEvents
		config.Kstream.EnableRegistryKevents = config.Kstream.EnableRegistryKevents && e.r.HasRegistryEvents
		config.Kstream.EnableFileIOKevents = config.Kstream.EnableFileIOKevents && e.r.HasFileEvents
		config.Kstream.EnableVAMapKevents = config.Kstream.EnableVAMapKevents && e.r.HasVAMapEvents
		config.Kstream.EnableMemKevents = config.Kstream.EnableMemKevents && e.r.HasMemEvents
		config.Kstream.EnableDNSEvents = config.Kstream.EnableDNSEvents && e.r.HasDNSEvents
		config.Kstream.EnableAuditAPIEvents = config.Kstream.EnableAuditAPIEvents && e.r.HasAuditAPIEvents
		for _, ktype := range ktypes.All() {
			if ktype == ktypes.CreateProcess || ktype == ktypes.TerminateProcess ||
				ktype == ktypes.LoadImage || ktype == ktypes.UnloadImage {
				// always allow fundamental events
				continue
			}
			if !e.r.ContainsEvent(ktype) {
				config.Kstream.SetDropMask(ktype)
			}
		}
	}

	e.addTrace(etw.KernelLoggerSession, etw.KernelTraceControlGUID)

	if SupportsSystemProviders() && !config.IsCaptureSet() {
		log.Info("system providers support detected")
		if config.Kstream.EnableRegistryKevents {
			e.addTraceKeywords(etw.SystemRegistrySession, etw.SystemRegistryProviderID, etw.RegistryKeywordGeneral)
		}
	}

	if config.Kstream.EnableDNSEvents {
		e.addTrace(etw.DNSClientSession, etw.DNSClientGUID)
	}
	if config.Kstream.EnableAuditAPIEvents {
		e.addTrace(etw.KernelAuditAPICallsSession, etw.KernelAuditAPICallsGUID)
	}

	for _, trace := range e.traces {
		err := trace.Start()
		switch err {
		case kerrors.ErrTraceAlreadyRunning:
			log.Debugf("%s trace is already running. Trying to restart...", trace.Name)
			if err := trace.Stop(); err != nil {
				return err
			}
			time.Sleep(time.Millisecond * 100)
			if err := trace.Start(); err != nil {
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

		// Init consumer and open the trace for processing
		consumer := NewConsumer(e.psnap, e.hsnap, config, e.sequencer, e.evts)
		consumer.SetFilter(e.filter)
		// Attach event listeners
		for _, lis := range e.listeners {
			consumer.q.RegisterListener(lis)
		}
		e.consumers = append(e.consumers, consumer)

		err = trace.Open(consumer, e.errs)
		if err != nil {
			return fmt.Errorf("unable to open %s trace: %v", trace.Name, err)
		}
		log.Infof("starting [%s] trace processing", trace.Name)

		// Start event processing loop
		errch := make(chan error)
		go trace.Process(errch)

		go func(trace *Trace) {
			select {
			case <-e.stop:
				return
			case err := <-errch:
				log.Infof("stopping [%s] trace processing", trace.Name)
				if err != nil && !errors.Is(err, kerrors.ErrTraceCancelled) {
					e.errs <- fmt.Errorf("unable to process %s trace: %v", trace.Name, err)
				}
			}
		}(trace)
	}

	return nil
}

// Close shutdowns all tracing sessions orderly. Firstly,
// the buffers are flushed. Then, the trace is closed to
// signal the event callback to stop consuming more events.
// Finally, the trace is stopped along with all event consumers.
func (e *EventSource) Close() error {
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

	return e.sequencer.Shutdown()
}

// Errors returns the channel where errors are published.
func (e *EventSource) Errors() <-chan error {
	return e.errs
}

// Events returns the buffered event channel.
func (e *EventSource) Events() <-chan *kevent.Kevent {
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
func (e *EventSource) RegisterEventListener(lis kevent.Listener) {
	e.listeners = append(e.listeners, lis)
}

func (e *EventSource) addTrace(name string, guid windows.GUID) {
	e.traces = append(e.traces, NewTrace(name, guid, 0x0, e.config))
}

func (e *EventSource) addTraceKeywords(name string, guid windows.GUID, keywords uint64) {
	e.traces = append(e.traces, NewTrace(name, guid, keywords, e.config))
}
