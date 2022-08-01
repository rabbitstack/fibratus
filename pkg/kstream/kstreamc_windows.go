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
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/kstream/interceptors"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/syscall/tdh"
	"github.com/rabbitstack/fibratus/pkg/syscall/thread"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	log "github.com/sirupsen/logrus"
)

const (
	// callbackNext is the return callback value which designates that callback execution should progress
	callbackNext = uintptr(1)
	// evtBufferSize determines the default buffer size in kilobytes for the`TraceEventInfo` structure
	evtBufferSize = uint32(4096)
)

var (
	// failedKevents counts the number of kevents that failed to process
	failedKevents                = expvar.NewMap("kstream.kevents.failures")
	failedKeventsByMissingSchema = expvar.NewMap("kstream.kevents.missing.schema.errors")
	// keventsEnqueued counts the number of events that are pushed to the queue
	keventsEnqueued = expvar.NewInt("kstream.kevents.enqueued")
	// failedKparams counts the number of kernel event parameters that failed to process
	failedKparams = expvar.NewInt("kstream.kevent.param.failures")

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
	openTrace       = etw.OpenTrace
	processTrace    = etw.ProcessTrace
	getPropertySize = tdh.GetPropertySize
	getProperty     = tdh.GetProperty

	currentPid = uint32(os.Getpid())
)

// Consumer is the interface for the kernel event stream consumer.
type Consumer interface {
	// OpenKstream initializes the kernel event stream by setting the event record callback and instructing it
	// to consume events from log buffers. This operation can fail if opening the kernel logger session results
	// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
	// blocks the current thread and we schedule its execution in a separate goroutine.
	OpenKstream() error
	// CloseKstream shutdowns the currently running kernel event stream consumer by closing the corresponding
	// session.
	CloseKstream() error
	// Errors returns the channel where errors are pushed.
	Errors() chan error
	// Events returns the buffered channel for pulling collected kernel events.
	Events() chan *kevent.Kevent
	// SetFilter initializes the filter that's applied on the kernel events.
	SetFilter(filter filter.Filter)
}

type kstreamConsumer struct {
	handles []etw.TraceHandle // trace session handles

	errs  chan error          // channel for event processing errors
	kevts chan *kevent.Kevent // channel for fanning out generated events

	interceptorChain interceptors.Chain
	ignoredKparams   map[string]bool // avoids parsing event parameters in this map
	config           *config.Config  // main configuration

	ktraceController KtraceController  // trace session control plane
	psnapshotter     ps.Snapshotter    // process state tracker
	sequencer        *kevent.Sequencer // event sequence manager

	filter filter.Filter
	rules  filter.Rules

	capture bool // capture determines whether the event capture is triggered
}

// NewConsumer constructs a new kernel event stream consumer.
func NewConsumer(ktraceController KtraceController, psnap ps.Snapshotter, hsnap handle.Snapshotter, config *config.Config) Consumer {
	kconsumer := &kstreamConsumer{
		errs:             make(chan error, 1000),
		ignoredKparams:   kparams.Ignored(),
		config:           config,
		psnapshotter:     psnap,
		ktraceController: ktraceController,
		capture:          config.KcapFile != "",
		sequencer:        kevent.NewSequencer(),
		kevts:            make(chan *kevent.Kevent),
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
func (k *kstreamConsumer) OpenKstream() error {
	err := k.openKstream(etw.KernelLoggerSession)
	if err != nil {
		return err
	}
	// try to compile rules
	if err := k.rules.Compile(); err != nil {
		for _, h := range k.handles {
			_ = etw.CloseTrace(h)
		}
		return err
	}
	err = k.openKstream(etw.KernelLoggerRundownSession)
	if err != nil {
		log.Warn(err)
	}
	err = k.openKstream(etw.KernelAuditAPICallsSession)
	if err != nil {
		log.Warn(err)
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

	traceHandle := openTrace(ktrace)
	if uint64(traceHandle) == winerrno.InvalidProcessTraceHandle {
		return fmt.Errorf("unable to open kernel trace: %v", syscall.GetLastError())
	}

	k.handles = append(k.handles, traceHandle)

	// since `ProcessTrace` blocks the current thread
	// we invoke it in a separate goroutine but send
	// any possible errors to the channel
	go func() {
		err := processTrace(traceHandle)
		log.Infof("stopping kernel trace processing for [%s]", loggerName)
		if err == nil {
			log.Infof("kernel trace processing successfully stopped for [%s]", loggerName)
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

// CloseKstream shutdowns the currently running kernel event stream consumer by closing the corresponding
// session.
func (k *kstreamConsumer) CloseKstream() error {
	for _, h := range k.handles {
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

// processKevent is the backbone of the kernel stream consumer. It does the heavy lifting of parsing inbound ETW events,
// iterating through event properties and pushing kernel events to the channel.
func (k *kstreamConsumer) processKevent(evt *etw.EventRecord) error {
	var (
		pid   = evt.Header.ProcessID
		tid   = evt.Header.ThreadID
		ktype ktypes.Ktype
		// get the CPU core on which the event was generated
		cpu = *(*uint8)(unsafe.Pointer(&evt.BufferContext.ProcessorIndex[0]))
	)

	// obtain the ktype from provider GUID + event type that varies
	// across different provider types. For the NT Kernel Logger provider
	// this is the `Opcode` field, while other providers utilize the `ID`
	// field to transport the event type value
	switch evt.Header.ProviderID {
	case etw.KernelAuditAPICallsGUID:
		ktype = ktypes.Pack(evt.Header.ProviderID, uint8(evt.Header.EventDescriptor.ID))
	default:
		ktype = ktypes.Pack(evt.Header.ProviderID, evt.Header.EventDescriptor.Opcode)
	}

	// drop unknown kernel events or excluded processes as soon as possible
	if !ktype.Exists() {
		return nil
	}
	if k.config.Kstream.ExcludeImage(k.psnapshotter.Find(pid)) {
		excludedProcs.Add(1)
		return nil
	}
	// it as required to initialize the size of the
	// event trace buffer that we'll have to reallocate
	// in case there's no enough room to store the whole trace
	bufferSize := evtBufferSize
	buffer := make([]byte, bufferSize)

	err := tdh.GetEventInformation(evt, buffer, bufferSize)
	if err == kerrors.ErrInsufficentBuffer {
		// not enough space to store the event, so we retry with bigger buffer
		buffer = make([]byte, bufferSize)
		if err = tdh.GetEventInformation(evt, buffer, bufferSize); err != nil {
			return fmt.Errorf("failed to get event metadata after reallocating buffer size to %d KB: %v", bufferSize, err)
		}
	}

	if err != nil {
		if err == kerrors.ErrEventSchemaNotFound {
			// increment error count for events that lack the schema
			failedKeventsByMissingSchema.Add(ktype.String(), 1)
			return fmt.Errorf("schema not found for event %q", ktype)
		}
		return fmt.Errorf("unable to retrieve kernel event metadata for :%q: %v", ktype, err)
	}

	trace := (*tdh.TraceEventInfo)(unsafe.Pointer(&buffer[0]))
	kpars := kevent.Kparams(k.produceParams(ktype, evt, trace))
	ts := filetime.ToEpoch(evt.Header.Timestamp)
	category := ktypes.KtypeToKeventInfo(ktype).Category

	switch category {
	case ktypes.Image:
		// sometimes the pid present in event header is invalid
		// but we can get the valid one from the event parameters
		if pid == winerrno.InvalidPID {
			pid, _ = kpars.GetUint32(kparams.ProcessID)
		}

	case ktypes.File:
		// on some Windows versions the value of
		// the PID attribute is invalid for the
		// file system kernel events
		if pid == winerrno.InvalidPID {
			// try to resolve a valid pid from thread ID
			threadID, err := kpars.GetHexAsUint32(kparams.ThreadID)
			if err != nil {
				break
			}
			h, err := thread.Open(thread.QueryLimitedInformation, false, threadID)
			if err != nil {
				break
			}
			defer h.Close()
			pid, err = process.GetPIDFromThread(h)
			if err != nil {
				log.Debugf("unable to get the pid from thread ID %d: %v", threadID, err)
			}
		}
		if pid != winerrno.InvalidPID {
			kpars.Append(kparams.ProcessID, kparams.PID, pid)
		}

	case ktypes.Process:
		// process and thread start events may be logged in the context of the parent process or thread.
		// As a result, the ProcessId and ThreadId members of EVENT_TRACE_HEADER may not correspond to the
		// process and thread being created so we set the event pid to be the one of the parent process
		if ktype == ktypes.CreateProcess {
			pid, _ = kpars.GetHexAsUint32(kparams.ProcessParentID)
		}

	case ktypes.Net:
		pid, _ = kpars.GetUint32(kparams.ProcessID)
		kpars.Remove(kparams.ProcessID)
	}

	// try to drop excluded processes after pid readjustment
	if k.config.Kstream.ExcludeImage(k.psnapshotter.Find(pid)) {
		excludedProcs.Add(1)
		return nil
	}

	// build a new kernel event with all required fields. Kevent is the fundamental data structure
	// for propagating events to outputs sinks.
	kevt := kevent.New(
		k.sequencer.Get(),
		pid,
		tid,
		cpu,
		ktype,
		ts,
		kpars,
	)

	// dispatch each event to the interceptor chain that will further augment the kernel
	// event with useful fields, route events to corresponding snapshotters or initialize
	// open files/registry control blocks at the beginning of the kernel trace session
	kevt, err = k.interceptorChain.Dispatch(kevt)
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
		kevt.PS = k.psnapshotter.Find(kevt.PID)
	}
	if k.isKeventDropped(kevt) {
		kevt.Release()
		return nil
	}
	// run rules. In case of rule groups with sequence policy
	// the last event matching the group is forwarded to the
	// outputs
	if rulesFired := k.rules.Fire(kevt); !rulesFired {
		return nil
	}
	// increment sequence
	if !kevt.Type.Dropped(false) {
		k.sequencer.Increment()
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

	k.kevts <- kevt

	keventsEnqueued.Add(1)
	k.sequencer.Increment()

	return nil
}

var offsets = map[uint32]string{}
var omux sync.RWMutex

// produceParams traverses ETW event's properties, gets the underlying property buffer and produces a kernel event
// parameter for the particular event.
func (k *kstreamConsumer) produceParams(ktype ktypes.Ktype, evt *etw.EventRecord, trace *tdh.TraceEventInfo) map[string]*kevent.Kparam {
	var (
		count = trace.PropertyCount
		kpars = make(map[string]*kevent.Kparam, count)
		// this yields a property array from the unsized array
		props = (*[1 << 30]tdh.EventPropertyInfo)(unsafe.Pointer(&trace.EventPropertyInfoArray[0]))[:count:count]
	)

	for _, property := range props {
		hashKey := ktype.Hash() + property.NameOffset
		omux.RLock()
		// lookup resolved kparam names if the hash key is not located in offsets cache
		kparName, ok := offsets[hashKey]
		omux.RUnlock()
		// compute the pointer to each property name and get the size of the buffer
		// that we'll allocate to accommodate the property value
		propp := unsafe.Pointer(uintptr(unsafe.Pointer(trace)) + uintptr(property.NameOffset))
		if !ok {
			kparName = utf16.PtrToString(propp)
			omux.Lock()
			offsets[hashKey] = kparName
			omux.Unlock()
		}

		// skip ignored parameters
		if _, ok := k.ignoredKparams[kparName]; ok {
			continue
		}
		kparName = kparams.Canonicalize(kparName)
		// discard unknown canonical names
		if kparName == "" {
			continue
		}

		descriptor := &tdh.PropertyDataDescriptor{
			PropertyName: propp,
			ArrayIndex:   0xFFFFFFFF,
		}
		// try to get the param size for static types
		// and fallback to TdhGetPropertySize for the
		// dynamic event parameters such as paths
		// process names, registry keys and so on
		size := kparams.SizeOf(kparName)
		if size == 0 {
			var err error
			size, err = getPropertySize(evt, descriptor)
			if err != nil || size == 0 {
				continue
			}
		}

		buffer := make([]byte, size)
		if err := getProperty(evt, descriptor, size, buffer); err != nil {
			continue
		}

		nst := *(*tdh.NonStructType)(unsafe.Pointer(&property.Types[0]))
		// obtain parameter value from the byte buffer
		kpar, err := getParam(kparName, buffer, size, nst)
		if err != nil {
			failedKparams.Add(1)
			continue
		}
		kpars[kparName] = kpar
	}

	return kpars
}

// getParam extracts parameter value from the property buffer and builds the kparam structure.
func getParam(name string, buffer []byte, size uint32, nonStructType tdh.NonStructType) (*kevent.Kparam, error) {
	if len(buffer) == 0 {
		return nil, errors.New("property buffer is empty")
	}

	var (
		typ   kparams.Type
		value kparams.Value
	)

	switch nonStructType.InType {
	case tdh.IntypeUnicodeString:
		typ, value = kparams.UnicodeString, utf16.PtrToString(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeAnsiString:
		typ, value = kparams.AnsiString, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buffer[0]))[:size-1:size-1])

	case tdh.IntypeInt8:
		typ, value = kparams.Int8, *(*int8)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeUint8:
		typ, value = kparams.Uint8, *(*uint8)(unsafe.Pointer(&buffer[0]))
		if nonStructType.OutType == tdh.OutypeHexInt8 {
			typ = kparams.HexInt8
		}
	case tdh.IntypeBoolean:
		typ, value = kparams.Bool, *(*bool)(unsafe.Pointer(&buffer[0]))

	case tdh.IntypeInt16:
		typ, value = kparams.Int16, *(*int16)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeUint16:
		typ, value = kparams.Uint16, *(*uint16)(unsafe.Pointer(&buffer[0]))
		switch nonStructType.OutType {
		case tdh.OutypeHexInt16:
			typ = kparams.HexInt16
		case tdh.OutypePort:
			typ = kparams.Port
		}

	case tdh.IntypeInt32:
		typ, value = kparams.Int32, *(*int32)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeUint32:
		typ, value = kparams.Uint32, *(*uint32)(unsafe.Pointer(&buffer[0]))
		switch nonStructType.OutType {
		case tdh.OutypeHexInt32:
			typ = kparams.HexInt32
		case tdh.OutypeIPv4:
			typ = kparams.IPv4
		}

	case tdh.IntypeInt64:
		typ, value = kparams.Int64, *(*int64)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeUint64:
		typ, value = kparams.Uint64, *(*uint64)(unsafe.Pointer(&buffer[0]))
		if nonStructType.OutType == tdh.OutypeHexInt64 {
			typ = kparams.HexInt64
		}

	case tdh.IntypeFloat:
		typ, value = kparams.Float, *(*float32)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeDouble:
		typ, value = kparams.Double, *(*float64)(unsafe.Pointer(&buffer[0]))

	case tdh.IntypeHexInt32:
		typ, value = kparams.HexInt32, *(*int32)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeHexInt64:
		typ, value = kparams.HexInt64, *(*int64)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypePointer, tdh.IntypeSizet:
		typ, value = kparams.HexInt64, *(*uint64)(unsafe.Pointer(&buffer[0]))
	case tdh.IntypeSID:
		typ, value = kparams.SID, buffer
	case tdh.IntypeWbemSID:
		typ, value = kparams.WbemSID, buffer
	case tdh.IntypeBinary:
		if nonStructType.OutType == tdh.OutypeIPv6 {
			typ, value = kparams.IPv6, buffer
		} else {
			typ, value = kparams.Binary, buffer
		}
	default:
		return nil, fmt.Errorf("unknown type for %q parameter", name)
	}

	return kevent.NewKparam(name, typ, value), nil
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
	// drops events of certain type. For example, EnumProcess
	// is solely used to create the snapshot of live processes
	if kevt.Type.Dropped(k.capture) {
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
