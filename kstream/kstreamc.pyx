# Copyright 2015 by Nedim Sabic (RabbitStack)
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


import socket
import struct
import re
import os
import traceback

from logbook import Logger, FileHandler


from cpython cimport PyBytes_AsString
from cpython.exc cimport PyErr_CheckSignals

from kstream.ktypedefs cimport *

cdef enum:
    GUID_LEN = 39
    MAX_NAME = 256

PID_PARAM_NAME = 'process_id'
TID_PARAM_NAME = 'thread_id'

REGISTRY_KEVENT_GUID = 'ae53722e-c863-11d2-8659-00c04fa321a1'

ENUM_PROCESS = ('3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c', 3)
ENUM_THREAD = ('3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c', 3)
ENUM_IMAGE = ('2cb15d1d-5fc1-11d2-abe1-00a0c911f518', 3)
REG_CREATE_KCB = ('ae53722e-c863-11d2-8659-00c04fa321a1', 22)
REG_DELETE_KCB = ('ae53722e-c863-11d2-8659-00c04fa321a1', 23)


cdef class KEventStreamCollector:
    """Kernel event stream collector.


    Collects events the from kernel event stream and invokes
    a python callback method for each event delivered
    to the collector.

    The main motivation behind this Cython extension are the perfomance reasons, where
    ETW can generate a huge volume of events, and the parsing
    process is very CPU intensive.

    Use
    ---

    kevt_stream_collector = KEventStreamCollector(logger_name)

    Register a python callback:

    def next_kevt(ketype, cpuid, ts, kparams):
        # your logic here
    kevt_stream_collector.open_kstream(next_kevt)


    """
    cdef EVENT_TRACE_LOGFILE kevent_logfile
    cdef TRACEHANDLE handle
    cdef next_kevt_callback
    cdef on_kstream_open_callback
    cdef klogger
    cdef pointer_size
    cdef property_regex
    cdef ketypes
    cdef own_pid
    cdef kefilters
    cdef exclude_pid_props
    cdef exclude_from_filters
    cdef logger
    cdef file_handler
    cdef interrupted
    cdef thread_registry
    cdef _filters
    cdef _excluded_procs

    def __init__(self, klogger, thread_registry):
        self.klogger = klogger
        self.handle = 0
        self.next_kevt_callback = None
        self.on_kstream_open_callback = None
        self.kevent_logfile.LoggerName = PyBytes_AsString(self.klogger)
        self.property_regex = re.compile('((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')
        self.pointer_size = 8
        self.ketypes = {}
        self.kefilters = []
        self._filters = []
        self._excluded_procs = []
        self.exclude_pid_props = ['process_id', 'parent_id', 'pid']
        self.exclude_from_filters = [ENUM_PROCESS, ENUM_THREAD, ENUM_IMAGE, REG_CREATE_KCB, REG_DELETE_KCB]
        self.logger = Logger(KEventStreamCollector.__name__)
        self.file_handler = FileHandler(os.path.join(os.path.expanduser('~'), '.fibratus', 'fibratus.log'), mode='a')
        self.own_pid = os.getpid()
        self.thread_registry = thread_registry
        self.interrupted = False

    def open_kstream(self, callback):
        """Initializes the kernel event stream.

        Sets the event record callback and open
        the trace to consume from kernel event
        stream.

        Parameters
        ----------

        callback: callable
            A python method which is called
            when kernel event is consumed successfully

        """
        self.next_kevt_callback = callback

        self.kevent_logfile.ProcessTraceMode = EVENT_TRACE_REAL_TIME_MODE | PROCESS_TRACE_MODE_EVENT_RECORD
        self.kevent_logfile.EventRecordCallback = <PEVENT_RECORD_CALLBACK> self.process_kevent_callback
        # because `process_kevent` callback is the instance
        # method and the ETW API expects a callback function with
        # single parameter, the `self` argument refers to
        # an invalid context. We need to inject the reference
        # to this instance into `Context` member.
        self.kevent_logfile.Context = <PVOID> self

        with self.file_handler.applicationbound():
            self.logger.info('Opening kernel event stream')
        self.handle = OpenTrace(&self.kevent_logfile)

        if self.on_kstream_open_callback:
            self.on_kstream_open_callback()

        # foward the kernel event stream
        # to the consumer and start the processing
        status = ProcessTrace(&self.handle,
                              1,
                              NULL,
                              NULL)

        if status != ERROR_SUCCESS or status != ERROR_CANCELLED:
            if status != INVALID_PROCESSTRACE_HANDLE:
                CloseTrace(self.handle)
            else:
                raise RuntimeError('ERROR - Unable to open kernel event stream. Error %s' % status)

    def set_kstream_open_callback(self, callback):
        self.on_kstream_open_callback = callback

    def close_kstream(self):
        CloseTrace(self.handle)

    def add_kevent_filter(self, kefilter):
        self.kefilters.append(kefilter)

    def add_pid_filter(self, pid):
        if pid:
            self._filters.append(lambda kpid: kpid != int(pid))

    def set_excluded_procs(self, excluded_procs):
        self._excluded_procs = excluded_procs

    def clear_kefilters(self):
        self.kefilters.clear()

    cdef process_kevent_callback(self,  EVENT_RECORD* kevent_trace):
        # remember we can`t use the `self` to refer to the instance
        # of the class. In case the better approach to access
        # the `self` exists, I would like to see it
        cdef KEventStreamCollector cself = <KEventStreamCollector> kevent_trace.UserContext
        if not cself.interrupted:
            cself._process_kevent(kevent_trace)

    cdef void _process_kevent(self, EVENT_RECORD* kevent_trace) except *:
        """Kernel event stream callback.

        Parameters
        ----------

        kevent_trace: EVENT_RECORD
            The pointer to kernel event metadata

        """
        cdef TRACE_EVENT_INFO* info = <TRACE_EVENT_INFO*> malloc(4096)
        cdef ULONG buffer_size = 4096
        cdef params = {}
        cdef BYTE* property_buffer
        cdef ULONG property_size
        cdef PROPERTY_DATA_DESCRIPTOR descriptor
        cdef dropped = False

        try:
            status = TdhGetEventInformation(kevent_trace,
                                            0,
                                            NULL,
                                            info,
                                            &buffer_size)
            # kernel event type within the
            # scope of the event GUID
            opcode = <BYTE> kevent_trace.EventHeader.EventDescriptor.Opcode
            # the cpu where the event has been captured
            cpuid = <UCHAR> kevent_trace.BufferContext.ProcessorNumber
            pid = <ULONG> kevent_trace.EventHeader.ProcessId
            tid = <ULONG> kevent_trace.EventHeader.ThreadId

            # we don't want to capture events
            # coming from the fibratus process
            # nor from the process we've declared
            # in the excluded process list
            if self.own_pid == pid or self._exclude_kevent(pid, tid):
                free(<void*> info)
                return

            # get the event type tuple
            # and apply filters if they
            # are passed from the CLI
            kevt_type = self._assemble_type(info.EventGuid, opcode)
            if kevt_type not in self.exclude_from_filters:
                if len(self.kefilters) > 0 and len(self._filters) == 0:
                    if kevt_type not in self.kefilters:
                        dropped = True
                elif len(self.kefilters) > 0 and len(self._filters) > 0:
                    for f in self._filters:
                        dropped = f(pid)
                elif len(self._filters) > 0:
                    for f in self._filters:
                        dropped = f(pid)

                # we got an invalid pid from the header
                # and we can't still drop the event
                if pid == 0xFFFFFFFF:
                    dropped = False

            if not dropped:
                if (kevent_trace.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) == \
                        EVENT_HEADER_FLAG_32_BIT_HEADER:
                    self.pointer_size = 4
                else:
                    self.pointer_size = 8

                # the call has succeed. We loop over event properties
                # and apply the parsing logic.
                # It is very important to release the memory allocated for the
                # `TRACE_EVENT_INFO` structure once we had
                # parsed the event properties. Otherwise, memory leaks can occur
                if status == ERROR_SUCCESS:
                    props = info.EventPropertyInfoArray
                    for i from 0 <= i < info.TopLevelPropertyCount:
                        property = <EVENT_PROPERTY_INFO> props[i]

                        property_name = <LPTSTR><BYTE*>info + property.NameOffset

                        # initialize the descriptor
                        # with the property name
                        descriptor.PropertyName = <ULONGLONG><BYTE*>info + property.NameOffset
                        descriptor.ArrayIndex = 0xFFFFFFFF

                        # get the property size which
                        # is used to allocate the buffer
                        TdhGetPropertySize(kevent_trace, 0, NULL,
                                           1,
                                           &descriptor,
                                           &property_size)
                        property_buffer = <BYTE* > malloc(property_size)

                        # fill the property buffer
                        status = TdhGetProperty(kevent_trace, 0, NULL,
                                                1,
                                                &descriptor,
                                                property_size,
                                                property_buffer)
                        # get the property value and store
                        # it in the parameter dictionary
                        if status == ERROR_SUCCESS:
                            param = self._parse_property(property.nonStructType.InType,
                                                         property.nonStructType.OutType,
                                                         property_buffer)
                            # convert the property name from
                            # camel case to underscore so we have
                            # PEP 8 compliant coding style
                            _property = self.property_regex.sub(r'_\1', property_name).lower()
                            if _property in self.exclude_pid_props:
                                if self.own_pid == param:
                                    self._free_buffers(info, property_buffer)
                                    return
                                elif len(self._filters) > 0:
                                    if kevt_type not in self.exclude_from_filters:
                                        for f in self._filters:
                                            if f(param):
                                                self._free_buffers(info, property_buffer)
                                                return
                            self._aggregate_info(kevent_trace, kevt_type, params)

                            params[_property] = param
                        # release property buffer memory
                        free(<void*> property_buffer)

                    ts = self._filetime_to_systime(kevent_trace.EventHeader)

                    # call the kernel event callback
                    # with the specified arguments
                    self.next_kevt_callback(kevt_type,
                                            cpuid,
                                            ts,
                                            params)
        except Exception as e:
            with self.file_handler.applicationbound():
                self.logger.error(traceback.format_exc())
        except KeyboardInterrupt:
            pass
        # claim the allocated memory
        free(<void*> info)
        # check for pending signals.
        # The default behaviour is to
        # raise `KeyboardInterrupt` exception
        # which will be propagated to the caller
        if PyErr_CheckSignals() > 0:
            self.interrupted = True
            self.close_kstream()
            return

    cdef _free_buffers(self, TRACE_EVENT_INFO* info_buffer, BYTE* property_buffer):
        free(property_buffer)
        free(info_buffer)

    cdef _parse_property(self, USHORT in_type, USHORT out_type, BYTE* buf):
        """Parses the property value.

        Given the property input / output types,
        transforms the buffer with property payload.

        Parameters
        ----------

        {in|out}_type : USHORT
            The property input/output types. fAn input type can
            have multiple output types. For example, UINT16 input
            type can have HEXINT16 or PORT output types.

        buffer: BYTE
            The pointer to the property buffer.

        """
        if buf == NULL:
            return None

        if in_type == TDH_INTYPE_UNICODESTRING:
            try:
                return bytes(<LPTSTR>buf, 'utf-8').decode('utf-8')
            except UnicodeDecodeError:
                return ''
        elif in_type == TDH_INTYPE_ANSISTRING:
            try:
                return (<LPSTR>buf).decode('utf-8')
            except UnicodeDecodeError:
                return ''
        elif in_type == TDH_INTYPE_INT8:
            return (<CHAR*>buf)[0]

        elif in_type == TDH_INTYPE_UINT8:
            if out_type == TDH_OUTTYPE_HEXINT8:
                return hex((<BYTE*>buf)[0])
            else:
                return (<BYTE*>buf)[0]

        elif in_type == TDH_INTYPE_POINTER or in_type == TDH_INTYPE_SIZET:
            if self.pointer_size == 8:
                return (<ULONGLONG*>buf)[0]
            else:
                return (<ULONG*>buf)[0]
        elif in_type == TDH_INTYPE_INT16:
            return (<SHORT*>buf)[0]

        elif in_type == TDH_INTYPE_UINT16:
            if out_type == TDH_OUTTYPE_HEXINT16:
                return hex((<USHORT*>buf)[0])
            elif out_type == TDH_OUTTYPE_PORT:
                try:
                    # we have to convert the integer
                    # from network byte order to
                    # host byte order
                    return socket.ntohs((<USHORT *>buf)[0])
                except TypeError:
                    return '0'
            else:
                return (<USHORT*>buf)[0]

        elif in_type == TDH_INTYPE_INT32:
            return (<LONG*>buf)[0]

        elif in_type == TDH_INTYPE_UINT32:
            if out_type == TDH_OUTTYPE_HEXINT32:
                return hex((<ULONG*>buf)[0])
            # IPv4 address
            elif out_type == TDH_OUTTYPE_IPV4:
                try:
                    # first convert the ip address
                    # from network to host byte order
                    ip = socket.htonl((<ULONG *>buf)[0])
                    return socket.inet_ntoa(struct.pack('!L', ip))
                except (TypeError, struct.error):
                    return '0.0.0.0'
            else:
                return (<ULONG *>buf)[0]

        elif in_type == TDH_INTYPE_INT64:
            return (<LONGLONG*>buf)[0]
        elif in_type == TDH_INTYPE_UINT64:
            if out_type == TDH_OUTTYPE_HEXINT64:
                return hex((<ULONGLONG*>buf)[0])
            else:
                return (<ULONGLONG*>buf)[0]

        elif in_type == TDH_INTYPE_HEXINT32:
             return hex((<ULONG*>buf)[0])
        elif in_type ==  TDH_INTYPE_HEXINT64:
            return hex((<ULONGLONG*>buf)[0])

        elif in_type == TDH_INTYPE_FLOAT:
            return (<FLOAT*>buf)[0]
        elif in_type == TDH_INTYPE_DOUBLE:
            return (<DOUBLE*>buf)[0]
        elif in_type == TDH_INTYPE_UNICODECHAR:
            return (<WCHAR*>buf)[0]
        elif in_type == TDH_INTYPE_ANSICHAR:
            return (<CHAR*>buf)[0]

        elif in_type == TDH_INTYPE_SID:
            # resolve account and domain name
            # from the SID (Security Identifier)
            return self._lookup_sid(buf, False)
        elif in_type == TDH_INTYPE_WBEMSID:
            # resolve account name and domain
            # from the WBEM SID (TOKEN_USER + SID)
            if (<ULONG*>buf)[0] > 0:
                return self._lookup_sid(buf, True)

    cdef _lookup_sid(self, BYTE* buf, BOOL wbem_sid):
        cdef wchar_t user_name[MAX_NAME]
        cdef wchar_t domain_name[MAX_NAME]
        cdef DWORD user_name_size = MAX_NAME
        cdef DWORD domain_name_size = MAX_NAME
        cdef SID_NAME_USE sid_type

        if wbem_sid:
            # adjust the size of the TOKEN_USER structure
            buf += self.pointer_size * 2

        if LookupAccountSid(NULL, <SID*>buf,
                            user_name,
                            &user_name_size,
                            domain_name,
                            &domain_name_size,
                            &sid_type):

            pass
            # I need help here ;(
        else:
            return 'unknown'

    cdef _assemble_type(self, GUID guid, UCHAR opcode):
        """Packs an event type into tuple.

        Casts the GUID to string representation and builds
        the tuple which contains the event GUID and the
        operational code. The tuple identifies the event
        type.

        Parameters
        ----------

        guid: GUID
            Global Unique Identifier for the
            kernel event.
        opcode: UCHAR
            Operational code

        """
        cdef wchar_t buf[GUID_LEN]
        kkey = '%s-%s-%s-%s-%d' % (guid.Data1, guid.Data2,
                                   guid.Data3, guid.Data4,
                                   opcode)
        # lookup for resolved
        # kernel event types
        if kkey in self.ketypes:
            return self.ketypes[kkey]
        else:
            # after the `StringFromGUID2` has been called,
            # the `buf` should contain a GUID null terminated string
            # including the enclosing braces
            chars = StringFromGUID2(&guid, buf, GUID_LEN)
            if chars < 0:
                # the buffer is too small
                return None
            pystr = <object> PyUnicode_FromWideChar(buf, GUID_LEN)
            # remove the braces/null terminator
            # from the GUID string
            pystr = pystr[1:-2].lower()
            self.ketypes[kkey] = pystr, opcode
            return pystr, opcode

    cdef _filetime_to_systime(self, EVENT_HEADER kevt_header):
        """Converts kernel event timestamp.

        Converts an event timestamp given in file time
        to zone local date and time.

        Parameters
        ----------

        kevt_header: EVENT_HEADER
            kernel event header

        """
        cdef FILETIME filet
        cdef SYSTEMTIME syst
        cdef SYSTEMTIME tzt

        filet.dwHighDateTime = kevt_header.TimeStamp.HighPart
        filet.dwLowDateTime = kevt_header.TimeStamp.LowPart

        # convert to currently active
        # time zone local date and time format
        FileTimeToSystemTime(&filet, &syst)
        SystemTimeToTzSpecificLocalTime(NULL,
                                        &syst,
                                        &tzt)
        return '%d:%02d:%02d.%d' % (tzt.wHour, tzt.wMinute,
                                    tzt.wSecond,
                                    tzt.wMilliseconds)

    cdef _exclude_kevent(self, pid, tid):
        """Excludes the kernel event from the pid or tid

        Parameters
        ----------

        pid: ULONG
            the identifier of the process which emitted the event
        tid: ULONG
            the identifier of the thread which belongs to the process

       """
        if len(self._excluded_procs) == 0:
            return False
        thread = self.thread_registry.get_thread(pid) or \
                 self.thread_registry.get_thread(tid)
        return True if thread and thread.name \
                                  in self._excluded_procs else False

    cdef _aggregate_info(self, EVENT_RECORD* kevent_trace, kevt_type, params):
        if REGISTRY_KEVENT_GUID == kevt_type[0]:
            # registry events have a valid process/thread
            # id in the event header.
            # Aggregate them to event payload
            params[TID_PARAM_NAME] = <ULONG> kevent_trace.EventHeader.ThreadId
            params[PID_PARAM_NAME] = <ULONG> kevent_trace.EventHeader.ProcessId

