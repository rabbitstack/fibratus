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
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/kstream/processors"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	log "github.com/sirupsen/logrus"
)

const (
	// callbackNext is the return callback value which designates that callback execution should progress
	callbackNext = uintptr(1)
)

// EventCallback is the type alias for ETW event/buffer callbacks
type EventCallback interface{}

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

// consumer is responsible for opening trace
// sessions and allocating event sinks.
// For each running session, a separate instance
// of the event sink is assigned.
type consumer struct {
	controller *Controller
	errs       chan error
	evts       chan *kevent.Kevent
	sequencer  *kevent.Sequencer
	eventSinks map[string]*sink
	config     *config.Config
	stop       chan struct{}
}

// sink receives events from the consumer
// process event callbacks, parses the event,
// runs registered listeners, and forwards
// events to the main output channel.
type sink struct {
	q          *kevent.Queue
	sequencer  *kevent.Sequencer
	processors processors.Chain
	psnap      ps.Snapshotter
	config     *config.Config
	errs       chan error
	filter     filter.Filter
	quit       chan struct{}
}

// NewConsumer constructs a new event stream consumer.
func NewConsumer(
	controller *Controller,
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Consumer {
	kconsumer := &consumer{
		eventSinks: make(map[string]*sink, 0),
		controller: controller,
		evts:       make(chan *kevent.Kevent, 500),
		errs:       make(chan error, 1000),
		config:     config,
		stop:       make(chan struct{}),
		sequencer:  kevent.NewSequencer(),
	}

	kconsumer.initSinks(psnap, hsnap)

	return kconsumer
}

// SetFilter sets the filter to run on every captured event.
func (k *consumer) SetFilter(filter filter.Filter) {
	for _, s := range k.eventSinks {
		s.filter = filter
	}
}

// Open initializes the event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening any tracing session
// results in an error.
func (k *consumer) Open() error {
	for _, trace := range k.controller.Traces() {
		if !trace.IsStarted() {
			continue
		}
		sink := k.eventSinks[trace.Name]
		if sink == nil {
			return fmt.Errorf("consumer sink not allocated for %s trace", trace.Name)
		}
		err := trace.Open(k.bufferStatsCallback, sink.processEventCallback)
		if err != nil {
			return fmt.Errorf("unable to open %s trace: %v", trace.Name, err)
		}
		log.Infof("starting [%s] trace processing", trace.Name)

		errch := make(chan error)
		go trace.Process(errch)

		go func(trace *Trace) {
			select {
			case <-k.stop:
				return
			case err := <-errch:
				log.Infof("stopping [%s] trace processing", trace.Name)
				if err != nil && !errors.Is(err, kerrors.ErrTraceCancelled) {
					k.errs <- fmt.Errorf("unable to process %s trace: %v", trace.Name, err)
				}
			}
		}(trace)
	}
	return nil
}

// Close shutdowns the event stream consumer by closing all running traces.
func (k *consumer) Close() error {
	for _, s := range k.eventSinks {
		err := s.stop()
		if err != nil {
			return err
		}
	}
	close(k.stop)
	return k.sequencer.Shutdown()
}

// RegisterEventListener registers a new event listener that is invoked before
// the event is pushed to the output queue.
func (k *consumer) RegisterEventListener(listener kevent.Listener) {
	for _, s := range k.eventSinks {
		s.q.RegisterListener(listener)
	}
}

// Errors returns a channel where errors are pushed.
func (k *consumer) Errors() <-chan error {
	return k.errs
}

// Events returns the buffered channel where collected events are pushed
func (k *consumer) Events() <-chan *kevent.Kevent {
	return k.evts
}

// bufferStatsCallback is periodically triggered by ETW subsystem for the purpose of reporting
// buffer statistics, such as the number of buffers processed.
func (k *consumer) bufferStatsCallback(logfile *etw.EventTraceLogfile) uintptr {
	buffersRead.Add(int64(logfile.BuffersRead))
	return callbackNext
}

// initSinks creates an event sink per tracing session.
func (k *consumer) initSinks(psnap ps.Snapshotter, hsnap handle.Snapshotter) {
	for _, trace := range k.controller.Traces() {
		s := &sink{
			q:          kevent.NewQueue(500, k.config.Kstream.StackEnrichment, k.config.ForwardMode || k.config.IsCaptureSet()),
			sequencer:  k.sequencer,
			processors: processors.NewChain(psnap, hsnap, k.config),
			psnap:      psnap,
			errs:       k.errs,
			config:     k.config,
			quit:       make(chan struct{}),
		}
		go s.run(k.evts)
		k.eventSinks[trace.Name] = s
	}
}

// run awaits events from the event queue and
// forwards to the main output channel.
func (s *sink) run(evts chan *kevent.Kevent) {
	for {
		select {
		case evt := <-s.q.Events():
			evts <- evt
		case <-s.quit:
			s.q.Close()
			return
		}
	}
}

// stop stops sink processing.
func (s *sink) stop() error {
	close(s.quit)
	return s.processors.Close()
}

// processEventCallback is the event callback function signature that is called each time
// a new event is available on the session buffer. It does the heavy lifting of parsing inbound
// ETW events from raw data buffers, building the state machine, and pushing events to the channel.
func (s *sink) processEventCallback(ev *etw.EventRecord) uintptr {
	if err := s.processEvent(ev); err != nil {
		s.errs <- err
		failedKevents.Add(err.Error(), 1)
	}
	return callbackNext
}

func (s *sink) processEvent(ev *etw.EventRecord) error {
	if kevent.IsCurrentProcDropped(ev.Header.ProcessID) {
		return nil
	}
	if s.config.Kstream.ExcludeKevent(ev.Header.ProviderID, ev.HookID()) {
		excludedKevents.Add(1)
		return nil
	}
	ktype := ktypes.NewFromEventRecord(ev)
	if !ktype.Exists() {
		keventsUnknown.Add(1)
		return nil
	}
	keventsProcessed.Add(1)
	evt := kevent.New(s.sequencer.Get(), ktype, ev)
	// Dispatch each event to the processor chain.
	// Processors may further augment the event with
	// useful fields or play the role of state managers.
	// Scanning open files and registry control blocks
	// at the beginning of the kernel trace session is an
	// example of state management
	var err error
	evt, err = s.processors.ProcessEvent(evt)
	if err != nil {
		return err
	}
	if evt.WaitEnqueue {
		return nil
	}
	ok, proc := s.psnap.Find(evt.PID)
	if !ok {
		s.psnap.Put(proc)
	}
	// Associate process' state with the event.
	// We only override the process' state if it hasn't
	// been set previously such as in the situation where
	// captures are being taken. Events that construct
	// the process' snapshot also have attached process
	// state, so simply by replaying the flow of these
	// events we are able to reconstruct system-wide
	// process state.
	if evt.PS == nil {
		evt.PS = proc
	}
	// Drop any events if it is originated by the
	// current process, state event, or if the
	// process image is in the exclusion list.
	// Stack walk events are forwarded to the
	// event queue for stack enrichment. Lastly,
	// the filter is evaluated on the event to
	// decide whether it should get dropped
	if (evt.IsDropped(s.config.IsCaptureSet()) ||
		s.config.Kstream.ExcludeImage(evt.PS)) && !evt.IsStackWalk() {
		keventsDropped.Add(1)
		return nil
	}
	if s.filter != nil && !evt.IsStackWalk() && !s.filter.Run(evt) {
		return nil
	}
	// Increment sequence
	if !evt.IsState() {
		s.sequencer.Increment()
	}
	return s.q.Push(evt)
}
