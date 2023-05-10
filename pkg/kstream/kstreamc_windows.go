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
	"golang.org/x/sys/windows"
)

const (
	// callbackNext is the return callback value which designates that callback execution should progress
	callbackNext = uintptr(1)
)

var (
	// failedKevents counts the number of kevents that failed to process
	failedKevents = expvar.NewMap("kstream.kevents.failures")
	// keventsEnqueued counts the number of events that are pushed to the queue
	keventsEnqueued = expvar.NewInt("kstream.kevents.enqueued")
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
	traces []etw.TraceHandle // trace session handles

	errs  chan error          // channel for event processing errors
	kevts chan *kevent.Kevent // channel for fanning out generated events

	processors processors.Chain

	config *config.Config // main configuration

	psnap     ps.Snapshotter    // process state tracker
	sequencer *kevent.Sequencer // event sequence manager

	filter filter.Filter

	capture        bool              // capture determines if events are dumped to capture files
	eventCallback  EventCallbackFunc // called on each incoming event
	eventAssembler *EventAssembler   // event assembler
}

func (k *consumer) addTrace(trace etw.TraceHandle) {
	k.traces = append(k.traces, trace)
}

// NewConsumer constructs a new event stream consumer.
func NewConsumer(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Consumer {
	kconsumer := &consumer{
		errs:       make(chan error, 1000),
		kevts:      make(chan *kevent.Kevent, 500),
		config:     config,
		psnap:      psnap,
		capture:    config.KcapFile != "",
		sequencer:  kevent.NewSequencer(),
		processors: processors.NewChain(psnap, hsnap, config),
	}
	kconsumer.eventAssembler = NewEventAssembler(kconsumer.kevts)
	return kconsumer
}

// SetFilter initializes the filter that's applied on events.
func (k *consumer) SetFilter(filter filter.Filter) { k.filter = filter }

// Open initializes the event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening the kernel logger session results
// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
// blocks the current thread, and we schedule its execution in a separate goroutine.
func (k *consumer) Open(sessions []TraceSession) error {
	for _, ses := range sessions {
		trace, err := k.openTrace(ses.Name)
		if err != nil {
			if ses.IsKernelLogger() {
				return err
			}
			log.Warnf("unable to open %s trace: %v", ses.Name, err)
		}
		if err == nil {
			k.addTrace(trace)
			k.processTrace(ses.Name, trace)
		}
	}
	return nil
}

func (k *consumer) openTrace(name string) (etw.TraceHandle, error) {
	logfile := etw.NewEventTraceLogfile(name)
	logfile.SetBufferCallback(windows.NewCallback(k.bufferStatsCallback))
	logfile.SetEventCallback(windows.NewCallback(k.processEventCallback))
	logfile.SetModes(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)
	trace := etw.OpenTrace(logfile)
	if !trace.IsValid() {
		return 0, fmt.Errorf("unable to open %s trace: %v", name, windows.GetLastError())
	}
	return trace, nil
}

func (k *consumer) processTrace(name string, trace etw.TraceHandle) {
	go func(trace etw.TraceHandle) {
		log.Infof("starting [%s] trace processing", name)
		err := etw.ProcessTrace(trace)
		log.Infof("stopping [%s] trace processing", name)
		if err == nil {
			log.Infof("[%s] trace processing stopped", name)
			return
		}
		if !errors.Is(err, kerrors.ErrTraceCancelled) {
			k.errs <- err
		}
	}(trace)
}

// Close shutdowns the event stream consumer by closing all running traces.
func (k *consumer) Close() error {
	for _, trace := range k.traces {
		if !trace.IsValid() {
			continue
		}
		if err := etw.CloseTrace(trace); err != nil {
			log.Warn(err)
		}
	}
	if err := k.sequencer.Store(); err != nil {
		log.Warn(err)
	}
	if err := k.sequencer.Close(); err != nil {
		log.Warn(err)
	}
	return k.processors.Close()
}

// Errors returns a channel where errors are pushed.
func (k *consumer) Errors() chan error {
	return k.errs
}

// Events returns the buffered channel for pulling collected kernel events.
func (k *consumer) Events() chan *kevent.Kevent {
	return k.kevts
}

// SetEventCallback sets the event callback to receive inbound events.
func (k *consumer) SetEventCallback(fn EventCallbackFunc) {
	k.eventCallback = fn
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
	if k.config.Kstream.ExcludeKevent(evt) {
		excludedKevents.Add(1)
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
	typ := ktypes.NewFromEventRecord(ev)
	if !typ.Exists() {
		keventsUnknown.Add(1)
		return nil
	}
	evt := kevent.New(k.sequencer.Get(), typ, ev)
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
	// Invoke event callback
	if k.eventCallback != nil {
		return k.eventCallback(evt)
	}
	// Run event assembler
	if !k.eventAssembler.Assemble(evt) {
		return nil
	}
	k.kevts <- evt
	keventsEnqueued.Add(1)
	return nil
}
