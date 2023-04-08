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
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kstream/processors"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	log "github.com/sirupsen/logrus"
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

	// excludedKevents counts the number of excluded events
	excludedKevents = expvar.NewInt("kstream.excluded.kevents")
	// excludedProcs counts the number of excluded events by image name
	excludedProcs = expvar.NewInt("kstream.excluded.procs")

	// buffersRead amount of buffers fetched from the ETW session
	buffersRead = expvar.NewInt("kstream.kbuffers.read")
)

type kstreamConsumer struct {
	traceHandles []etw.TraceHandle // trace session handles

	errs  chan error          // channel for event processing errors
	kevts chan *kevent.Kevent // channel for fanning out generated events

	processors processors.Chain

	config *config.Config // main configuration

	psnap     ps.Snapshotter    // process state tracker
	sequencer *kevent.Sequencer // event sequence manager

	filter filter.Filter

	capture       bool              // capture determines if events are dumped to capture files
	eventCallback EventCallbackFunc // called on each incoming event
}

func (k *kstreamConsumer) addTraceHandle(traceHandle etw.TraceHandle) {
	k.traceHandles = append(k.traceHandles, traceHandle)
}

// NewConsumer constructs a new event stream consumer.
func NewConsumer(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Consumer {
	kconsumer := &kstreamConsumer{
		errs:       make(chan error, 1000),
		kevts:      make(chan *kevent.Kevent, 500),
		config:     config,
		psnap:      psnap,
		capture:    config.KcapFile != "",
		sequencer:  kevent.NewSequencer(),
		processors: processors.NewChain(psnap, hsnap, config),
	}

	return kconsumer
}

// SetFilter initializes the filter that's applied on events.
func (k *kstreamConsumer) SetFilter(filter filter.Filter) { k.filter = filter }

// OpenKstream initializes the event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening the kernel logger session results
// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
// blocks the current thread, and we schedule its execution in a separate goroutine.
func (k *kstreamConsumer) OpenKstream(traces map[string]TraceSession) error {
	for _, trace := range traces {
		err := k.openKstream(trace.Name)
		if err != nil {
			if trace.IsKernelLogger() {
				return err
			}
			log.Warnf("unable to open %s trace: %v", trace.Name, err)
		}
	}
	return nil
}

func (k *kstreamConsumer) openKstream(loggerName string) error {
	trace := etw.EventTraceLogfile{
		LoggerName:     windows.StringToUTF16Ptr(loggerName),
		BufferCallback: syscall.NewCallback(k.bufferStatsCallback),
	}
	fn := syscall.NewCallback(k.processEventCallback)
	modes := uint32(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)
	// initialize real time trace mode and event callback functions
	// via these nasty pointer accesses to unions inside the structure
	*(*uint32)(unsafe.Pointer(&trace.LogFileMode[0])) = modes
	*(*uintptr)(unsafe.Pointer(&trace.EventCallback[4])) = fn

	traceHandle := etw.OpenTrace(trace)
	if !traceHandle.IsValid() {
		return fmt.Errorf("unable to open kernel trace: %v", syscall.GetLastError())
	}
	k.addTraceHandle(traceHandle)

	// since `ProcessTrace` blocks the current thread
	// we invoke it in a separate goroutine but send
	// any possible errors to the errors channel
	go func() {
		log.Infof("starting trace processing for [%s]", loggerName)
		err := etw.ProcessTrace(traceHandle)
		log.Infof("stopping trace processing for [%s]", loggerName)
		if err == nil {
			log.Infof("trace processing successfully stopped for [%s]", loggerName)
			return
		}
		if errors.Is(err, kerrors.ErrTraceCancelled) {
			if traceHandle.IsValid() {
				if err := etw.CloseTrace(traceHandle); err != nil {
					k.errs <- err
				}
			}
		} else {
			k.errs <- err
		}
	}()
	return nil
}

// CloseKstream shutdowns the event stream consumer by closing all running traces.
func (k *kstreamConsumer) CloseKstream() error {
	for _, h := range k.traceHandles {
		if err := etw.CloseTrace(h); err != nil {
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
func (k *kstreamConsumer) Errors() chan error {
	return k.errs
}

// Events returns the buffered channel for pulling collected kernel events.
func (k *kstreamConsumer) Events() chan *kevent.Kevent {
	return k.kevts
}

// SetEventCallback sets the event callback to receive inbound events.
func (k *kstreamConsumer) SetEventCallback(f EventCallbackFunc) {
	k.eventCallback = f
}

// bufferStatsCallback is periodically triggered by ETW subsystem for the purpose of reporting
// buffer statistics, such as the number of buffers processed.
func (k *kstreamConsumer) bufferStatsCallback(logfile *etw.EventTraceLogfile) uintptr {
	buffersRead.Add(int64(logfile.BuffersRead))
	return callbackNext
}

// processEventCallback is the event callback function signature that is called each time
// a new event is available on the session buffer. It does the heavy lifting of parsing inbound
// ETW events from raw data buffers, building the state machine, and pushing events to the channel.
func (k *kstreamConsumer) processEventCallback(ev *etw.EventRecord) uintptr {
	if err := k.processEvent(ev); err != nil {
		k.errs <- err
		failedKevents.Add(err.Error(), 1)
	}
	return callbackNext
}

func (k *kstreamConsumer) isEventDropped(evt *kevent.Kevent) bool {
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

func (k *kstreamConsumer) processEvent(ev *etw.EventRecord) error {
	evt := kevent.New(k.sequencer.Get(), ev)
	if evt == nil {
		return nil
	}
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
	if k.isEventDropped(evt) {
		evt.Release()
		keventsDropped.Add(1)
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
	// Increment sequence
	if !evt.IsState() {
		k.sequencer.Increment()
	}
	// Invoke callback function
	if k.eventCallback != nil {
		return k.eventCallback(evt)
	}
	k.kevts <- evt
	keventsEnqueued.Add(1)
	return nil
}
