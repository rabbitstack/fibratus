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
	"os"
	"strings"
	"syscall"
	"unsafe"
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
	failedKparams      = expvar.NewInt("kstream.kevent.param.failures")
	blacklistedKevents = expvar.NewMap("kstream.blacklist.dropped.kevents")
	blacklistedProcs   = expvar.NewMap("kstream.blacklist.dropped.procs")

	upstreamCancellations = expvar.NewInt("kstream.upstream.cancellations")

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

type blacklist map[ktypes.Ktype]string

func (b blacklist) has(ktype ktypes.Ktype) bool { return b[ktype] != "" }

type kstreamConsumer struct {
	handle           etw.TraceHandle
	errs             chan error
	kevts            chan *kevent.Kevent
	interceptorChain interceptors.Chain
	ignoredKparams   map[string]bool
	config           *config.Config

	keventsBlacklist blacklist
	procsBlacklist   []string

	kstreamRundownConsumer Consumer

	ktraceController KtraceController

	psnapshotter ps.Snapshotter
	sequencer    *kevent.Sequencer

	filter  filter.Filter
	capture bool
}

// NewConsumer constructs a new kernel event stream consumer.
func NewConsumer(ktraceController KtraceController, psnap ps.Snapshotter, hsnap handle.Snapshotter, config *config.Config) Consumer {
	kconsumer := &kstreamConsumer{
		errs:                   make(chan error, 1000),
		ignoredKparams:         kparams.Ignored(),
		config:                 config,
		psnapshotter:           psnap,
		kstreamRundownConsumer: newRundownConsumer(),
		ktraceController:       ktraceController,
		procsBlacklist:         make([]string, len(config.Kstream.BlacklistImages)),
		keventsBlacklist:       make(map[ktypes.Ktype]string),
		capture:                config.KcapFile != "",
		sequencer:              kevent.NewSequencer(),
		kevts:                  make(chan *kevent.Kevent),
	}

	kconsumer.interceptorChain = interceptors.NewChain(psnap, hsnap, kconsumer.startRundown, config)

	return kconsumer
}

func (k *kstreamConsumer) startRundown() error {
	if err := k.ktraceController.StartKtraceRundown(); err != nil {
		return err
	}
	go k.openRundownConsumer()
	return nil
}

func (k *kstreamConsumer) init() {
	if k.ktraceController.IsKRundownStarted() {
		go k.openRundownConsumer()
	}

	for _, name := range k.config.Kstream.BlacklistKevents {
		if ktype := ktypes.KeventNameToKtype(name); ktype != ktypes.UnknownKtype {
			k.keventsBlacklist[ktype] = name
		}
	}

	for i, name := range k.config.Kstream.BlacklistImages {
		k.procsBlacklist[i] = strings.ToLower(name)
	}
}

// SetFilter initializes the filter that's applied on the kernel events.
func (k *kstreamConsumer) SetFilter(filter filter.Filter) { k.filter = filter }

// OpenKstream initializes the kernel event stream by setting the event record callback and instructing it
// to consume events from log buffers. This operation can fail if opening the kernel logger session results
// in an invalid trace handler. Errors returned by `ProcessTrace` are sent to the channel since this function
// blocks the current thread and we schedule its execution in a separate goroutine.
func (k *kstreamConsumer) OpenKstream() error {
	ktrace := etw.EventTraceLogfile{
		LoggerName:     utf16.StringToUTF16Ptr(etw.KernelLoggerSession),
		BufferCallback: syscall.NewCallback(k.bufferStatsCallback),
	}
	cb := syscall.NewCallback(k.processKeventCallback)
	modes := uint32(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)
	// initialize real time trace mode and event callback functions
	// via these nasty pointer accesses to unions inside the structure
	*(*uint32)(unsafe.Pointer(&ktrace.LogFileMode[0])) = modes
	*(*uintptr)(unsafe.Pointer(&ktrace.EventCallback[4])) = cb

	h := openTrace(ktrace)
	if uint64(h) == winerrno.InvalidProcessTraceHandle {
		return fmt.Errorf("unable to open kernel trace: %v", syscall.GetLastError())
	}
	k.handle = h
	k.init()
	// since `ProcessTrace` blocks the current thread
	// we invoke it in a separate goroutine but send
	// any possible errors to the channel
	go func() {
		err := processTrace(h)
		log.Info("stopping kernel trace processing")
		if err == nil {
			log.Info("kernel trace processing successfully stopped")
			return
		}
		switch err {
		case kerrors.ErrTraceCancelled:
			if uint64(h) != winerrno.InvalidProcessTraceHandle {
				if err := etw.CloseTrace(h); err != nil {
					k.errs <- err
				}
			}
		default:
			k.errs <- err
		}
	}()
	return nil
}

func (k *kstreamConsumer) openRundownConsumer() {
	if err := k.kstreamRundownConsumer.OpenKstream(); err != nil {
		log.Error(err)
		return
	}
	for {
		select {
		case kevt := <-k.kstreamRundownConsumer.Events():
			if _, err := k.interceptorChain.Dispatch(kevt); err != nil {
				log.Errorf("unable to dispatch rundown event to interceptors: %v", err)
			}
		case err := <-k.kstreamRundownConsumer.Errors():
			log.Errorf("got kernel rundown error: %v", err)
		}
	}
}

// CloseKstream shutdowns the currently running kernel event stream consumer by closing the corresponding
// session.
func (k *kstreamConsumer) CloseKstream() error {
	if err := etw.CloseTrace(k.handle); err != nil {
		return err
	}
	if err := k.sequencer.Store(); err != nil {
		log.Warn(err)
	}
	if err := k.sequencer.Close(); err != nil {
		log.Warn(err)
	}
	if k.ktraceController.IsKRundownStarted() {
		if err := k.kstreamRundownConsumer.CloseKstream(); err != nil {
			return err
		}
	}
	return nil
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
		pid = evt.Header.ProcessID
		tid = evt.Header.ThreadID
		// get the CPU core on which the event was generated
		cpu   = *(*uint8)(unsafe.Pointer(&evt.BufferContext.ProcessorIndex[0]))
		ktype = ktypes.Pack(evt.Header.ProviderID, evt.Header.EventDescriptor.Opcode)
	)

	// drop any blacklisted process or unknown kernel event as earliest as possible
	if k.dropBlacklistProc(pid) || !ktype.Exists() {
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
		}
		if pid != winerrno.InvalidPID {
			kpars.Append(kparams.ProcessID, kparams.PID, pid)
		}

	case ktypes.Process:
		// process and thread start events may be logged in the context of the parent process or thread.
		// As a result, the ProcessId and ThreadId members of EVENT_TRACE_HEADER may not correspond to the
		// process and thread being created so we set the event pid to be the one of the parent process
		pid, _ = kpars.GetHexAsUint32(kparams.ProcessParentID)

	case ktypes.Net:
		pid, _ = kpars.GetUint32(kparams.ProcessID)
		kpars.Remove(kparams.ProcessID)
	}

	// try to drop blacklist processes after pid readjustment
	if k.dropBlacklistProc(pid) {
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
	if k.isDropped(kevt) {
		kevt.Release()
		return nil
	}

	k.kevts <- kevt

	keventsEnqueued.Add(1)
	if !kevt.Type.Dropped(false) {
		k.sequencer.Increment()
	}

	return nil
}

var offsets = map[uint32]string{}

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
		// lookup resolved kparam names if the hash key is not located in offsets cache
		kparName, ok := offsets[hashKey]
		// compute the pointer to each property name and get the size of the buffer
		// that we'll allocate to accommodate the property value
		propp := unsafe.Pointer(uintptr(unsafe.Pointer(trace)) + uintptr(property.NameOffset))
		if !ok {
			kparName = utf16.PtrToString(propp)
			offsets[hashKey] = kparName
		}

		// skip ignored parameters
		if _, ok := k.ignoredKparams[kparName]; ok {
			continue
		}

		descriptor := &tdh.PropertyDataDescriptor{
			PropertyName: propp,
			ArrayIndex:   0xFFFFFFFF,
		}
		size, err := getPropertySize(evt, descriptor)
		if err != nil || size == 0 {
			continue
		}

		buffer := make([]byte, size)
		if err := getProperty(evt, descriptor, size, buffer); err != nil {
			continue
		}

		kparName = kparams.Canonicalize(kparName)
		// discard unknown canonical names
		if kparName == "" {
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
	if buffer == nil || len(buffer) == 0 {
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

// isDropped discards the kernel event before it hits the output channel.
// Dropping a kernel event occurs if any of the following conditions
// are met:
//
// - kernel event is used solely for building internal state of either
// needs to be stored in the capture file for the purpose of restoring
// the state
// - process that produced the kernel event is fibratus itself
// - kernel event is present in the blacklist, and thus it is always dropped
// - finally, the event is dropped by the filter engine
func (k *kstreamConsumer) isDropped(kevt *kevent.Kevent) bool {
	if kevt.Type.Dropped(k.capture) {
		return true
	}
	if kevt.PID == currentPid {
		return true
	}
	if k.keventsBlacklist.has(kevt.Type) {
		blacklistedKevents.Add(kevt.Name, 1)
		return true
	}
	if k.filter == nil {
		return false
	}
	filtered := k.filter.Run(kevt)
	if !filtered {
		return true
	}
	return false
}

// dropBlacklistProc drops the events from the blacklist if it is linked to particular process name.
func (k *kstreamConsumer) dropBlacklistProc(pid uint32) bool {
	if len(k.procsBlacklist) == 0 {
		return false
	}
	proc := k.psnapshotter.Find(pid)
	if proc == nil {
		return false
	}
	for _, blacklistProc := range k.procsBlacklist {
		if strings.ToLower(proc.Name) == blacklistProc {
			blacklistedProcs.Add(proc.Name, int64(1))
			return true
		}
	}
	return false
}
