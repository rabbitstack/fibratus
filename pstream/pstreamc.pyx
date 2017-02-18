# Copyright 2017 by Nedim Sabic (RabbitStack)
# http://rabbitstack.github.io
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from kstream.includes.etw cimport *
from kstream.includes.tdh cimport *
from kstream.includes.windows cimport *
from kstream.includes.python cimport *
from kstream.includes.stdlib cimport *

from cpython cimport PyBytes_AsString

cdef class PStreamCollector:
    """Packet stream collector.

    It acquires raw frames from the NIDS ETW provider
    an then delegates the processing to decoders in
    order to parse the packet and extract the available
    TCP/IP layers.

    """
    cdef EVENT_TRACE_LOGFILE ptrace

    cdef layers

    cdef next_packet_callback
    cdef klogger

    def __init__(self, klogger):
        self.klogger = klogger
        self.next_packet_callback = None
        self.ptrace.logger_name = PyBytes_AsString(self.klogger)
        self.layers = {}

        self.__register_layers()

    def open_packet_flow(self, callback):
        """Initializes the packet stream.

        Starts processing the packet stream trace.

        Parameters
        ----------

        callback: callable
            A python method which is called
            when decoded packet layers are
            forwarded from the `_process_packet` method.

        """
        self.next_packet_callback = callback

        self.ptrace.trace_mode = EVENT_TRACE_REAL_TIME_MODE | PROCESS_TRACE_MODE_EVENT_RECORD
        self.ptrace.callback = <PEVENT_RECORD_CALLBACK> self.process_packet
        # because `process_kevent` callback is the instance
        # method and the ETW API expects a callback function with
        # single parameter, the `self` argument refers to
        # invalid context. We need to inject the reference
        # to this instance into `Context` member.
        self.ptrace.context = <PVOID> self
        cdef TRACEHANDLE handle = open_trace(&self.ptrace)
        status = process_trace(&handle,
                              1,
                              NULL,
                              NULL)

        if status != ERROR_SUCCESS or status != ERROR_CANCELLED:
            if status != INVALID_PROCESSTRACE_HANDLE:
                close_trace(handle)
            raise RuntimeError('Unable to open packet stream. Error %s' % status)

    cdef process_packet(self,  EVENT_RECORD* pevent_trace):
        with nogil:
            (<PStreamCollector>pevent_trace.user_ctx)._process_packet(pevent_trace)


    cdef __register_layers(self):
        self.layers = {
            'ethernet': Ethernet()
        }

    cdef void _process_packet(self, EVENT_RECORD* pevent_trace) nogil:
        """Packet stream callback.

        Parameters
        ----------

        pevent_trace: EVENT_RECORD
            the pointer to ETW struct which stores
            the event data.

        """
        cdef TRACE_EVENT_INFO* info = <TRACE_EVENT_INFO*> malloc(4096)
        cdef ULONG buffer_size = 4096
        cdef BYTE* packet = NULL
        cdef ULONG packet_size
        cdef PROPERTY_DATA_DESCRIPTOR descriptor

        # the allocation has failed probably
        # because there is no enough memory
        if info == NULL:
            return

        cdef EVENT_HEADER pevt_hdr = pevent_trace.header

        status = tdh_get_event_information(pevent_trace,
                                           0,
                                           NULL,
                                           info,
                                           &buffer_size)

        cpuid = <UCHAR> pevent_trace.buffer_ctx.cpuid
        pid = <ULONG> pevt_hdr.process_id
        tid = <ULONG> pevt_hdr.thread_id

        if status == ERROR_SUCCESS:
            props = info.properties
            for i from 0 <= i < info.property_count:
                prop = <EVENT_PROPERTY_INFO> props[i]
                property_name = <LPTSTR><BYTE*>info \
                                + prop.name_offset
                # extract the raw frame data.
                # The property which stores the
                # memory buffer has `TDH_INTYPE_BINARY` type
                if prop.non_struct_type.in_type == TDH_INTYPE_BINARY:
                    descriptor.property_name = <ULONGLONG><BYTE*>info \
                                               + prop.name_offset
                    descriptor.array_index = 0xFFFFFFFF

                    tdh_get_property_size(pevent_trace,
                                          0,
                                          NULL,
                                          1,
                                          &descriptor,
                                          &packet_size)
                    # `packet_size` now holds the length
                    # in bytes of the packet pulled from the wire
                    packet = <BYTE* > malloc(packet_size)
                    if packet == NULL:
                        return

                    # get packet memory buffer
                    status = tdh_get_property(pevent_trace,
                                              0,
                                              NULL,
                                              1,
                                              &descriptor,
                                              packet_size,
                                              packet)

                    if status == ERROR_SUCCESS:
                        free(packet)
                        with gil:
                            for layer_type, layer in self.layers.items():
                                (<BaseLayer>layer).decode(<byte[:packet_size]>packet)
                                if self.next_packet_callback:
                                    self.next_packet_callback(layer_type,
                                                             (<BaseLayer>layer).serialize())
                    else:
                        if packet != NULL:
                            free(packet)
                        break


        free(<void*> info)

include "layers/base.pyx"
include "layers/ethernet.pyx"