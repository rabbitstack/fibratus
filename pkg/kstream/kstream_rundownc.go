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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/tdh"
	"github.com/rabbitstack/fibratus/pkg/syscall/utf16"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	log "github.com/sirupsen/logrus"
	"syscall"
	"unsafe"
)

// kstreamRundownConsumer publishes opened file objects as encountered at the beginning of the trace session.
type kstreamRundownConsumer struct {
	handle    etw.TraceHandle
	errs      chan error
	krundowns chan *kevent.Kevent
}

func newRundownConsumer() Consumer {
	return &kstreamRundownConsumer{
		errs:      make(chan error),
		krundowns: make(chan *kevent.Kevent, 1000),
	}
}

func (k *kstreamRundownConsumer) OpenKstream() error {
	ktrace := etw.EventTraceLogfile{
		LoggerName: utf16.StringToUTF16Ptr(etw.KernelLoggerRundownSession),
	}
	cb := syscall.NewCallback(k.processRundownCallback)
	modes := uint32(etw.ProcessTraceModeRealtime | etw.ProcessTraceModeEventRecord)
	*(*uint32)(unsafe.Pointer(&ktrace.LogFileMode[0])) = modes
	*(*uintptr)(unsafe.Pointer(&ktrace.EventCallback[4])) = cb

	handle := openTrace(ktrace)
	if uint64(handle) == winerrno.InvalidProcessTraceHandle {
		return fmt.Errorf("unable to open kernel rundown logger trace: %v", syscall.GetLastError())
	}
	k.handle = handle
	go func() {
		err := processTrace(handle)
		if err != nil {
			k.errs <- err
			return
		}
		log.Info("successfully stopped kernel rundown session")
	}()
	return nil
}

// SetFilter initializes the filter that's applied on the kernel events.
func (k *kstreamRundownConsumer) SetFilter(filter filter.Filter) {}

// CloseKstream shutdowns the currently running kernel rundown consumer by closing the corresponding
// session.
func (k *kstreamRundownConsumer) CloseKstream() error {
	return etw.CloseTrace(k.handle)
}

// Errors returns a channel where errors are pushed.
func (k *kstreamRundownConsumer) Errors() chan error {
	return k.errs
}

// Events returns the buffered channel where enumerated system resources are pushed.
func (k *kstreamRundownConsumer) Events() chan *kevent.Kevent {
	return k.krundowns
}

func (k *kstreamRundownConsumer) processRundownCallback(evt *etw.EventRecord) uintptr {
	if err := k.processRundown(evt); err != nil {
		k.errs <- err
	}
	return callbackNext
}

func (k *kstreamRundownConsumer) processRundown(evt *etw.EventRecord) error {
	bufferSize := evtBufferSize
	buffer := make([]byte, bufferSize)

	ktype := ktypes.Pack(evt.Header.ProviderID, evt.Header.EventDescriptor.Opcode)

	err := tdh.GetEventInformation(evt, buffer, bufferSize)
	if err == kerrors.ErrInsufficentBuffer {
		// not enough space to store the event, so we retry with bigger buffer
		buffer = make([]byte, bufferSize)
		if err = tdh.GetEventInformation(evt, buffer, bufferSize); err != nil {
			return fmt.Errorf("failed to get rundown event after reallocating buffer size to %d KB: %v", bufferSize, err)
		}
	}
	trace := (*tdh.TraceEventInfo)(unsafe.Pointer(&buffer[0]))
	kpars := kevent.Kparams(produceParams(evt, trace))

	krundown := &kevent.Kevent{
		Type:    ktype,
		Kparams: kpars,
	}

	select {
	case k.krundowns <- krundown:
	default:
		log.Warn("kernel rundown logger event queue is full")
	}

	return nil
}

// produceParams extracts event's parameters from the event descriptor.
func produceParams(evt *etw.EventRecord, trace *tdh.TraceEventInfo) map[string]*kevent.Kparam {
	var (
		count = trace.PropertyCount
		kpars = make(map[string]*kevent.Kparam, count)
		// this yields a property array from unsized array
		props = (*[1 << 30]tdh.EventPropertyInfo)(unsafe.Pointer(&trace.EventPropertyInfoArray[0]))[:count:count]
	)

	for _, property := range props {
		// compute the pointer to each property name and get the size of the buffer
		// that we'll allocate to accommodate the property value
		propp := unsafe.Pointer(uintptr(unsafe.Pointer(trace)) + uintptr(property.NameOffset))
		kparName := syscall.UTF16ToString((*[1 << 20]uint16)(propp)[:])

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
		// obtain the parameter value from byte buffer
		kpar, err := getParam(kparName, buffer, size, nst)
		if err != nil {
			continue
		}
		kpars[kparName] = kpar
	}
	return kpars
}
