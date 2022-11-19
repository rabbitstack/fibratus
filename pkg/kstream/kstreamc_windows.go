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
	"expvar"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/kstream/interceptors"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
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

	// excludedKevents counts the number of excluded events
	excludedKevents = expvar.NewInt("kstream.excluded.kevents")
	// excludedProcs counts the number of excluded events by image name
	excludedProcs = expvar.NewInt("kstream.excluded.procs")

	// upstreamCancellations counts the event cancellations in interceptors
	upstreamCancellations = expvar.NewInt("kstream.upstream.cancellations")

	// buffersRead amount of buffers fetched from the ETW session
	buffersRead = expvar.NewInt("kstream.kbuffers.read")
)

var (
	currentPid = uint32(os.Getpid())
)

// EventCallbackFunc is the type alias for the event callback function
type EventCallbackFunc func(*kevent.Kevent) error

// Consumer is the interface for the kernel event stream consumer.
type Consumer interface {
	// OpenKstream initializes the kernel event stream by setting the event record callback and instructing it
	// to consume events from log buffers. This operation can fail if opening the kernel logger session results
	// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
	// blocks the current thread and we schedule its execution in a separate goroutine.
	OpenKstream(traces map[string]TraceSession) error
	// CloseKstream shutdowns the currently running kernel event stream consumer by closing the corresponding
	// session.
	CloseKstream() error
	// Errors returns the channel where errors are pushed.
	Errors() chan error
	// Events returns the buffered channel for pulling collected kernel events.
	Events() chan *kevent.Kevent
	// SetFilter initializes the filter that's applied on the kernel events.
	SetFilter(filter.Filter)
	// SetEventCallback registers a callback function that is invoked for
	// each incoming event. If the callback function is set up, the events
	// channel doesn't receive any inbound events.
	SetEventCallback(EventCallbackFunc)
}

type kstreamConsumer struct {
	traceHandles []etw.TraceHandle // trace session handles

	errs  chan error          // channel for event processing errors
	kevts chan *kevent.Kevent // channel for fanning out generated events

	interceptorChain interceptors.Chain
	config           *config.Config // main configuration

	ktraceController KtraceController  // trace session control plane
	psnapshotter     ps.Snapshotter    // process state tracker
	sequencer        *kevent.Sequencer // event sequence manager

	filter filter.Filter
	rules  filter.Rules

	capture bool // capture determines whether the event capture is triggered

	eventCallback EventCallbackFunc // called on each incoming event
}

func (k *kstreamConsumer) addTraceHandle(traceHandle etw.TraceHandle) {
	k.traceHandles = append(k.traceHandles, traceHandle)
}

// NewConsumer constructs a new event stream consumer.
func NewConsumer(
	ktraceController KtraceController,
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Consumer {
	kconsumer := &kstreamConsumer{
		errs:             make(chan error, 1000),
		config:           config,
		psnapshotter:     psnap,
		ktraceController: ktraceController,
		capture:          config.KcapFile != "",
		sequencer:        kevent.NewSequencer(),
		kevts:            make(chan *kevent.Kevent, 500),
		rules:            filter.NewRules(config),
	}

	kconsumer.interceptorChain = interceptors.NewChain(psnap, hsnap, config, kconsumer.enqueueKevent)

	return kconsumer
}

// SetFilter initializes the filter that's applied on the kernel events.
func (k *kstreamConsumer) SetFilter(filter filter.Filter) { k.filter = filter }

// OpenKstream initializes the kernel event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening the kernel logger session results
// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
// blocks the current thread, and we schedule its execution in a separate goroutine.
func (k *kstreamConsumer) OpenKstream(traces map[string]TraceSession) error {
	err := k.rules.Compile()
	if err != nil {
		return err
	}
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
	ktrace := etw.EventTraceLogfile{
		LoggerName:     utf16.StringToUTF16Ptr(loggerName),
		BufferCallback: syscall.NewCallback(k.bufferStatsCallback),
	}
	cb := syscall.NewCallback(k.processKeventCallback)
	modes := uint32(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)
	// initialize real time trace mode and event callback functions
	// via these nasty pointer accesses to unions inside the structure
	*(*uint32)(unsafe.Pointer(&ktrace.LogFileMode[0])) = modes
	*(*uintptr)(unsafe.Pointer(&ktrace.EventCallback[4])) = cb

	traceHandle := etw.OpenTrace(ktrace)
	if uint64(traceHandle) == winerrno.InvalidProcessTraceHandle {
		return fmt.Errorf("unable to open kernel trace: %v", syscall.GetLastError())
	}
	k.addTraceHandle(traceHandle)

	// since `ProcessTrace` blocks the current thread
	// we invoke it in a separate goroutine but send
	// any possible errors to the channel
	go func() {
		log.Infof("starting trace processing for [%s]", loggerName)
		err := etw.ProcessTrace(traceHandle)
		log.Infof("stopping trace processing for [%s]", loggerName)
		if err == nil {
			log.Infof("trace processing successfully stopped for [%s]", loggerName)
			return
		}
		switch err {
		case kerrors.ErrTraceCancelled:
			if uint64(traceHandle) != winerrno.InvalidProcessTraceHandle {
				if err := etw.CloseTrace(traceHandle); err != nil {
					k.errs <- err
				}
			}
		default:
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

	return k.interceptorChain.Close()
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

// processKeventCallback is the event callback function signature that delegates event processing
// to `processKevent`.
func (k *kstreamConsumer) processKeventCallback(evt *etw.EventRecord) uintptr {
	if err := k.processKevent(evt); err != nil {
		failedKevents.Add(err.Error(), 1)
		k.errs <- err
	}
	return callbackNext
}

// processKevent is the backbone of the kernel stream consumer.
// It does the heavy lifting of parsing inbound ETW events,
// building the state machine, and pushing events to the channel.
func (k *kstreamConsumer) processKevent(evt *etw.EventRecord) error {
	var (
		ktype      ktypes.Ktype
		providerID = evt.Header.ProviderID
	)
	switch providerID {
	case etw.KernelAuditAPICallsGUID, etw.AntimalwareEngineGUID:
		ktype = ktypes.Pack(providerID, uint8(evt.Header.EventDescriptor.ID))
	default:
		ktype = ktypes.Pack(providerID, evt.Header.EventDescriptor.Opcode)
	}

	if !ktype.Exists() {
		return nil
	}
	kevt := kevent.New(
		k.sequencer.Get(),
		ktype,
		evt,
	)
	switch kevt.Category {
	case ktypes.Image:
		// sometimes the pid present in event header is invalid
		// but, we can get the valid one from the event parameters
		if kevt.PID == winerrno.InvalidPID {
			kevt.PID, _ = kevt.Kparams.GetPpid()
		}
	case ktypes.File:
		// on some Windows versions the value of
		// the PID attribute is invalid for the
		// file system kernel events
		if kevt.PID == winerrno.InvalidPID {
			// try to resolve a valid pid from thread ID
			threadID, err := kevt.Kparams.GetTid()
			if err != nil {
				break
			}
			pid, err := process.GetPIDFromThread(threadID)
			if err == nil {
				kevt.PID = pid
			}
		}
	case ktypes.Process:
		// process start events may be logged in the context of the parent or child process.
		// As a result, the ProcessId member of EVENT_TRACE_HEADER may not correspond to the
		// process being created, so we set the event pid to be the one of the parent process
		if ktype == ktypes.CreateProcess {
			kevt.PID, _ = kevt.Kparams.GetPpid()
		}
	case ktypes.Net:
		kevt.PID, _ = kevt.Kparams.GetPid()
	}

	// try to drop excluded processes
	proc := k.psnapshotter.Find(kevt.PID)
	if k.config.Kstream.ExcludeImage(proc) {
		excludedProcs.Add(1)
		return nil
	}

	// dispatch each event to the interceptor chain that will further augment the kernel
	// event with useful fields, route events to corresponding snapshotters or initialize
	// open files/registry control blocks at the beginning of the kernel trace session
	kevt, err := k.interceptorChain.Dispatch(kevt)
	if err != nil {
		if kerrors.IsCancelUpstreamKevent(err) {
			upstreamCancellations.Add(1)
			return nil
		}
		log.Errorf("interceptor chain error(s) occurred: %v", err)
	}

	// associate process' state with the kernel event. We only override the process'
	// state if it hasn't been set previously like in the situation where captures
	// are being taken. The kernel events that construct the process' snapshot also
	// have attached process state, so simply by replaying the flow of these events
	// we are able to reconstruct system-wide process state.
	if kevt.PS == nil {
		kevt.PS = proc
	}
	if k.isKeventDropped(kevt) {
		kevt.Release()
		return nil
	}
	// increment sequence
	if !kevt.Type.OnlyState() {
		k.sequencer.Increment()
	}
	// run rules. In case of rule groups with sequence policy
	// the last event matching the group is forwarded to the
	// outputs
	if rulesFired := k.rules.Fire(kevt); !rulesFired {
		return nil
	}
	if k.eventCallback != nil {
		return k.eventCallback(kevt)
	}

	k.kevts <- kevt
	keventsEnqueued.Add(1)

	return nil
}

// enqueueKevent is the callback method invoked on deferred event arrival.
func (k *kstreamConsumer) enqueueKevent(kevt *kevent.Kevent) error {
	if kevt.PS == nil {
		kevt.PS = k.psnapshotter.Find(kevt.PID)
	}
	if k.config.Kstream.ExcludeImage(kevt.PS) {
		excludedProcs.Add(1)
		return nil
	}
	if k.isKeventDropped(kevt) {
		kevt.Release()
		return nil
	}
	if rulesFired := k.rules.Fire(kevt); !rulesFired {
		return nil
	}
	// increment sequence
	if !kevt.Type.OnlyState() {
		k.sequencer.Increment()
	}
	if k.eventCallback != nil {
		return k.eventCallback(kevt)
	}

	k.kevts <- kevt
	keventsEnqueued.Add(1)

	return nil
}

// isKeventDropped discards the kernel event before it hits the output channel.
// Dropping a kernel event occurs if any of the following conditions
// are met:
//
// - kernel event is used solely for building internal state of either
// needs to be stored in the capture file for the purpose of restoring
// the state
// - process that produced the kernel event is fibratus itself
// - kernel event is present in the exclude list, and thus it is always dropped
// - finally, the event is checked by the CLI filter
func (k *kstreamConsumer) isKeventDropped(kevt *kevent.Kevent) bool {
	// drop events used for state management unless we're writing the capture
	if kevt.Type.OnlyState() && !k.capture {
		return true
	}
	// ignores anything produced by the fibratus process
	if kevt.PID == currentPid {
		return true
	}
	// discard excluded event types
	if k.config.Kstream.ExcludeKevent(kevt) {
		excludedKevents.Add(1)
		return true
	}
	// fallback to CLI filter
	if k.filter != nil {
		return !k.filter.Run(kevt)
	}
	return false
}
