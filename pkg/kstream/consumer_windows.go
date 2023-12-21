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
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
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
	// excludedProcs counts the number of excluded events by process executable image name
	excludedProcs = expvar.NewInt("kstream.excluded.procs")

	// buffersRead amount of buffers fetched from the ETW session
	buffersRead = expvar.NewInt("kstream.kbuffers.read")
)

type consumer struct {
	controller *Controller

	errs      chan error
	q         *kevent.Queue
	sequencer *kevent.Sequencer

	processors processors.Chain

	config *config.Config

	psnap ps.Snapshotter

	filter filter.Filter

	// capture indicates if events are dumped to capture files
	capture bool

	stop chan struct{}
}

// NewConsumer constructs a new event stream consumer.
func NewConsumer(
	controller *Controller,
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Consumer {
	kconsumer := &consumer{
		controller: controller,
		errs:       make(chan error, 1000),
		q:          kevent.NewQueue(500),
		config:     config,
		psnap:      psnap,
		capture:    config.KcapFile != "",
		sequencer:  kevent.NewSequencer(),
		processors: processors.NewChain(psnap, hsnap, config),
		stop:       make(chan struct{}),
	}
	return kconsumer
}

// SetFilter sets the filter to run on every captured event.
func (k *consumer) SetFilter(filter filter.Filter) { k.filter = filter }

// Open initializes the event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening any tracing session
// results in an error.
func (k *consumer) Open() error {
	for _, trace := range k.controller.Traces() {
		if !trace.IsStarted() {
			continue
		}
		err := trace.Open(k.bufferStatsCallback, k.processEventCallback)
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
	close(k.stop)
	return multierror.Wrap(k.sequencer.Shutdown(), k.processors.Close())
}

// RegisterEventListener registers a new event listener that is invoked before
// the event is pushed to the output queue.
func (k *consumer) RegisterEventListener(listener kevent.Listener) {
	k.q.RegisterListener(listener)
}

// Errors returns a channel where errors are pushed.
func (k *consumer) Errors() <-chan error {
	return k.errs
}

// Events returns the buffered channel where collected events are pushed
func (k *consumer) Events() <-chan *kevent.Kevent {
	return k.q.Events()
}

// bufferStatsCallback is periodically triggered by ETW subsystem for the purpose of reporting
// buffer statistics, such as the number of buffers processed.
func (k *consumer) bufferStatsCallback(logfile *etw.EventTraceLogfile) uintptr {
	buffersRead.Add(int64(logfile.BuffersRead))
	return callbackNext
}

// processEventCallback is the event callback function signature that is called each time
// a new event is available on the session buffer. It does the heavy lifting of parsing inbound
// ETW events from raw data buffers, building the state machine, and pushing events to the channel.
func (k *consumer) processEventCallback(ev *etw.EventRecord) uintptr {
	if err := k.processEvent(ev); err != nil {
		k.errs <- err
		failedKevents.Add(err.Error(), 1)
	}
	return callbackNext
}

func (k *consumer) isEventDropped(evt *kevent.Kevent) bool {
	if evt.IsDropped(k.capture) {
		return true
	}
	if k.config.Kstream.ExcludeImage(evt.PS) {
		excludedProcs.Add(1)
		return true
	}
	if k.filter != nil {
		return !k.filter.Run(evt)
	}
	return false
}

func (k *consumer) processEvent(ev *etw.EventRecord) error {
	if kevent.IsCurrentProcDropped(ev.Header.ProcessID) {
		return nil
	}
	ktype := ktypes.NewFromEventRecord(ev)
	if !ktype.Exists() {
		keventsUnknown.Add(1)
		return nil
	}
	if k.config.Kstream.ExcludeKevent(ktype) {
		excludedKevents.Add(1)
		return nil
	}
	keventsProcessed.Add(1)
	evt := kevent.New(k.sequencer.Get(), ktype, ev)
	// Dispatch each event to the processor chain.
	// Processors may further augment the event with
	// useful fields or play the role of state managers.
	// Scanning open files and registry control blocks
	// at the beginning of the kernel trace session is an
	// example of state management
	var err error
	evt, err = k.processors.ProcessEvent(evt)
	if err != nil {
		return err
	}
	if evt.WaitEnqueue {
		return nil
	}
	ok, proc := k.psnap.Find(evt.PID)
	if !ok {
		k.psnap.Put(proc)
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
	if k.isEventDropped(evt) {
		evt.Release()
		keventsDropped.Add(1)
		return nil
	}
	// Increment sequence
	if !evt.IsState() {
		k.sequencer.Increment()
	}
	return k.q.Push(evt)
}
