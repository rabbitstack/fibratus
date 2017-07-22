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

import re
import os
import traceback

from libcpp.unordered_map cimport unordered_map
from cython.operator cimport dereference as deref, preincrement as inc
from libcpp.vector cimport vector
from libcpp.utility cimport pair

from cpython cimport PyBytes_AsString
from cpython.exc cimport PyErr_CheckSignals

from kstream.includes.etw cimport *
from kstream.includes.tdh cimport *
from kstream.includes.windows cimport *
from kstream.includes.python cimport *
from kstream.includes.stdlib cimport *
from kstream.includes.string cimport *
from kstream.time cimport sys_time
from kstream.ktuple cimport build_ktuple
from kstream.process cimport PROCESS_INFO, THREAD_INFO, pid_from_tid


cdef enum:
    GUID_LENGTH = 36
    INVALID_PID = 4294967295

cdef PyObject* ENUM_PROCESS = build_ktuple(<PyObject*>'{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}', 3)
cdef PyObject* ENUM_THREAD = build_ktuple(<PyObject*>'{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}', 3)
cdef PyObject* ENUM_IMAGE = build_ktuple(<PyObject*>'{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}', 3)
cdef PyObject* REG_CREATE_KCB = build_ktuple(<PyObject*>'{ae53722e-c863-11d2-8659-00c04fa321a1}', 22)
cdef PyObject* REG_DELETE_KCB = build_ktuple(<PyObject*>'{ae53722e-c863-11d2-8659-00c04fa321a1}', 23)

cdef PyObject* CREATE_PROCESS = build_ktuple(<PyObject*>'{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}', 1)
cdef PyObject* CREATE_THREAD = build_ktuple(<PyObject*>'{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}', 1)
cdef PyObject* TERMINATE_THREAD = build_ktuple(<PyObject*>'{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}', 2)
cdef PyObject* TERMINATE_PROCESS = build_ktuple(<PyObject*>'{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}', 2)

cdef PyObject* CREATE_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 64)
cdef PyObject* WRITE_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 68)
cdef PyObject* READ_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 67)
cdef PyObject* DELETE_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 70)
cdef PyObject* CLOSE_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 66)
cdef PyObject* RENAME_FILE = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 71)
cdef PyObject* SET_FILE_INFORMATION = build_ktuple(<PyObject*>'{90cbdc39-4a3e-11d1-84f4-0000f80464e3}', 69)

cdef PyObject* UNLOAD_IMAGE =  build_ktuple(<PyObject*>'{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}', 2)

cdef wstring PID_PROP = deref_prop("PID")
cdef wstring PPID_PROP = deref_prop("ParentId")
cdef wstring PROCESS_ID_PROP = deref_prop("ProcessId")
cdef wstring FS_THREAD_ID_PROP = deref_prop("TTID")
cdef wstring THREAD_ID_PROP = deref_prop("TThreadId")
cdef wstring IMAGE_FILE_NAME_PROP = deref_prop("ImageFileName")

REGISTRY_KGUID = '{ae53722e-c863-11d2-8659-00c04fa321a1}'
FS_KGUID = '{90cbdc39-4a3e-11d1-84f4-0000f80464e3}'


cdef class KEventStreamCollector:
    """Kernel event stream collector.


    Collects events from the kernel event stream and invokes
    a python callback method for each event delivered
    to the collector.

    The main motivation behind this Cython extension are the perfomance reasons, where
    ETW can generate a huge volume of events, and the parsing
    process is very CPU intensive.

    Use
    ---

    kevt_stream_collector = KEventStreamCollector(logger_name)

    Register a python callback:

    def next_kevt(ktype, cpuid, ts, kparams):
        # your logic here
    kevt_stream_collector.open_kstream(next_kevt)


    """
    cdef EVENT_TRACE_LOGFILE ktrace
    cdef TRACEHANDLE handle
    cdef int pointer_size

    cdef vector[PyObject*]* ktuple_filters
    cdef vector[wchar_t*]* skips
    cdef unordered_map[ULONG, PROCESS_INFO]* proc_map
    cdef unordered_map[ULONG, THREAD_INFO]* thread_map

    cdef ULONG pid_filter
    cdef wchar_t* image_filter
    cdef ULONG own_pid

    cdef next_kevt_callback
    cdef on_kstream_open_callback
    cdef klogger
    cdef regex

    def __init__(self, klogger):
        self.klogger = klogger
        self.handle = 0
        self.next_kevt_callback = None
        self.on_kstream_open_callback = None
        self.ktrace.logger_name = PyBytes_AsString(self.klogger)
        self.regex = re.compile('((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')
        self.pointer_size = 8
        self.ktuple_filters = new vector[PyObject*]()
        self.proc_map = new unordered_map[ULONG, PROCESS_INFO]()
        self.thread_map = new unordered_map[ULONG, THREAD_INFO]()
        self.skips = new vector[wchar_t*]()
        self.pid_filter = 0
        self.image_filter = NULL
        self.own_pid = <ULONG>os.getpid()

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

        self.ktrace.trace_mode = EVENT_TRACE_REAL_TIME_MODE | PROCESS_TRACE_MODE_EVENT_RECORD
        self.ktrace.callback = <PEVENT_RECORD_CALLBACK> self.process_kevent_callback
        # because `process_kevent` callback is the instance
        # method and the ETW API expects a callback function with
        # single parameter, the `self` argument refers to
        # an invalid context. We need to inject the reference
        # to this instance into `Context` member.
        self.ktrace.context = <PVOID> self

        self.handle = open_trace(&self.ktrace)

        if self.on_kstream_open_callback:
            self.on_kstream_open_callback()

        # foward the kernel event stream
        # to the consumer and start the processing
        status = process_trace(&self.handle, 1,
                               NULL,
                               NULL)
        if status != ERROR_SUCCESS or status != ERROR_CANCELLED:
            if status != INVALID_PROCESSTRACE_HANDLE:
                close_trace(self.handle)
            else:
                raise RuntimeError('ERROR - Unable to open kernel event stream. Error %s' % status)

    def close_kstream(self):
        close_trace(self.handle)

    def set_kstream_open_callback(self, callback):
        self.on_kstream_open_callback = callback

    def add_skip(self, skip):
        self.skips.push_back(_wchar_t(<PyObject*>skip))

    def add_ktuple_filter(self, ktuple):
        kguid, opcode = ktuple
        self.ktuple_filters.push_back(build_ktuple(<PyObject*>kguid, <UCHAR>opcode))

    def add_pid_filter(self, pid):
        self.pid_filter = <ULONG>int(pid) if pid else 0

    def add_image_filter(self, image):
        self.image_filter = _wchar_t(<PyObject*>image) if image else NULL

    cdef process_kevent_callback(self, EVENT_RECORD* kevent_trace):
        with nogil:
            (<KEventStreamCollector>kevent_trace.user_ctx)._process_kevent(kevent_trace)

    cdef void _process_kevent(self, EVENT_RECORD* kevent_trace) nogil except *:
        """Kernel event stream callback.

        Parameters
        ----------

        kevent_trace: EVENT_RECORD
            The pointer to kernel event metadata

        """
        cdef TRACE_EVENT_INFO* info = <TRACE_EVENT_INFO*> malloc(4096)

        # the allocation has failed probably
        # because there is no enough memory
        if info == NULL:
            return

        cdef EVENT_HEADER kevt_hdr = kevent_trace.header
        cdef ULONG buffer_size = 4096
        cdef unordered_map[wstring, PyObject*] params
        cdef ULONG property_size
        cdef PROPERTY_DATA_DESCRIPTOR descriptor
        cdef BOOL dropped = False
        cdef PROCESS_INFO pi
        cdef THREAD_INFO ti

        status = tdh_get_event_information(kevent_trace, 0,
                                           NULL,
                                           info,
                                           &buffer_size)

        cpuid = <UCHAR> kevent_trace.buffer_ctx.cpuid
        opcode = <BYTE> kevt_hdr.descriptor.opcode
        pid = <ULONG> kevt_hdr.process_id
        tid = <ULONG> kevt_hdr.thread_id

        ktuple = self.__wrap_ktuple(info.event_guid, opcode)
        # this shouldn't happen, but just in
        # case simply discard the kernel event
        if ktuple == NULL:
            free(info)
            return
        dropped = self.__apply_filters(pid, tid, ktuple, params, True)

        if dropped:
            with gil:
                free(info)
                Py_XDECREF(ktuple)
            return

        if (kevt_hdr.flags & EVENT_HEADER_FLAG_32_BIT_HEADER) == \
                EVENT_HEADER_FLAG_32_BIT_HEADER:
            self.pointer_size = 4
        else:
            self.pointer_size = 8

        if status == ERROR_SUCCESS:
            props = info.properties
            for i from 0 <= i < info.property_count:
                prop = <EVENT_PROPERTY_INFO> props[i]

                property_name = <LPTSTR><BYTE*>info + prop.name_offset

                descriptor.property_name = <ULONGLONG><BYTE*>info + \
                                           prop.name_offset
                descriptor.array_index = 0xFFFFFFFF

                # get the property size which
                # is used to allocate the buffer
                tdh_get_property_size(kevent_trace, 0,
                                      NULL,
                                      1,
                                      &descriptor,
                                      &property_size)
                property_buffer = <BYTE*> malloc(property_size)
                if property_buffer == NULL:
                    return

                # fill the property buffer
                status = tdh_get_property(kevent_trace, 0,
                                          NULL,
                                          1,
                                          &descriptor,
                                          property_size,
                                          property_buffer)
                # get the property value and store it in the map
                if status == ERROR_SUCCESS:
                    if property_name != NULL:
                        mapk = new wstring(<wchar_t*>property_name)
                        params[deref(mapk)] = \
                            self.__parse_property(prop.non_struct_type.in_type,
                                                  prop.non_struct_type.out_type,
                                                  property_buffer)
                        del mapk
                    free(property_buffer)
                else:
                    if property_buffer != NULL:
                        free(property_buffer)

            free(info)
            ts = sys_time(kevt_hdr.timestamp)

            # build a tiny state machine around the
            # currently running processes/threads on the system
            if self.__ktuple_equals(ktuple, ENUM_PROCESS) or \
                self.__ktuple_equals(ktuple, CREATE_PROCESS):
                pi.pid = <ULONG>wcstol(_wchar_t(params.at(PROCESS_ID_PROP)), NULL, 16)
                pi.ppid = <ULONG>wcstol(_wchar_t(params.at(PPID_PROP)), NULL, 16)
                pi.name = _wchar_t(params.at(IMAGE_FILE_NAME_PROP))
                k = new pair[ULONG, PROCESS_INFO](<ULONG>wcstol(_wchar_t(params.at(PROCESS_ID_PROP)), NULL, 16),
                                                 pi)
                self.proc_map.insert(deref(k))
                del k
            elif self.__ktuple_equals(ktuple, ENUM_THREAD) or \
                self.__ktuple_equals(ktuple, CREATE_THREAD):
                ti.tid = <ULONG>wcstol(_wchar_t(params.at(THREAD_ID_PROP)), NULL, 16)
                ti.pid = <ULONG>wcstol(_wchar_t(params.at(PROCESS_ID_PROP)), NULL, 16)
                tk = new pair[ULONG, THREAD_INFO](<ULONG>wcstol(_wchar_t(params.at(THREAD_ID_PROP)), NULL, 16),
                                                  ti)
                self.thread_map.insert(deref(tk))
                del tk
            elif self.__ktuple_equals(ktuple, TERMINATE_THREAD):
                prop_tid = <ULONG>wcstol(_wchar_t(params.at(THREAD_ID_PROP)), NULL, 16)
                self.thread_map.erase(prop_tid)
            elif self.__ktuple_equals(ktuple, TERMINATE_PROCESS):
                # defer the removal of the pid to be able to capture
                # `TerminateProcess` if the image filter is set
                if self.image_filter == NULL:
                    prop_pid = <ULONG>wcstol(_wchar_t(params.at(PROCESS_ID_PROP)), NULL, 16)
                    self.proc_map.erase(prop_pid)
            elif self.__ktuple_equals(ktuple, CREATE_FILE) or \
                self.__ktuple_equals(ktuple, WRITE_FILE) or \
                self.__ktuple_equals(ktuple, READ_FILE) or \
                self.__ktuple_equals(ktuple, DELETE_FILE) or \
                self.__ktuple_equals(ktuple, CLOSE_FILE) or \
                self.__ktuple_equals(ktuple, RENAME_FILE) or \
                self.__ktuple_equals(ktuple, SET_FILE_INFORMATION):
                # on some Windows versions the value of
                # the PID attribute is invalid for the
                # file system kernel events
                if pid == INVALID_PID:
                    prop_fs_tid = params.at(FS_THREAD_ID_PROP)
                    if prop_fs_tid != NULL:
                        # try to resolve the pid from the thread id
                        pid = pid_from_tid(PyLong_AsLong(prop_fs_tid),
                                           self.thread_map)
            elif self.__ktuple_equals(ktuple, UNLOAD_IMAGE):
                # on Windows 7 the pid field of the event header
                # is invalid, so use the pid found in the event params
                if pid == INVALID_PID:
                    p = params.at(PROCESS_ID_PROP)
                    if p != NULL:
                        pid = PyLong_AsLong(p)

            dropped = self.__apply_filters(pid, tid, ktuple, params, False)
            # now we can erase the pid
            if self.image_filter != NULL and \
                    self.__ktuple_equals(ktuple, TERMINATE_PROCESS):
                prop_pid = <ULONG>wcstol(_wchar_t(params.at(PROCESS_ID_PROP)), NULL, 16)
                self.proc_map.erase(prop_pid)
            if dropped:
                with gil:
                    # decrement references to avoid memory leaks
                    if self.image_filter != NULL:
                       self._decref_params(params)
                    Py_XDECREF(ktuple)
                return
            with gil:
                # check for pending signals.
                # The default behaviour is to
                # raise `KeyboardInterrupt` exception
                # which will be propagated to the caller
                if PyErr_CheckSignals() > 0:
                    self.close_kstream()
                    return
                try:
                    timestamp = '%d-%d-%d %d:%02d:%02d.%d' % (ts.year, ts.month,
                                                              ts.day, ts.hour,
                                                              ts.minute, ts.second,
                                                              ts.millis)
                    # convert the property name from
                    # camel case to underscore so we have
                    # PEP 8 compliant coding style
                    kparams = {self._underscore(self._decref(_wstring(kparam.first))): self._decref(kparam.second)
                               for kparam in params
                               if kparam.second != NULL}
                    kguid, opc = <object>ktuple
                    kguid = kguid[:-1]
                    # registry events have a valid process/thread id
                    # in the event header so we aggregate them
                    if kguid in REGISTRY_KGUID:
                        kparams['thread_id']  = tid
                        kparams['process_id'] = pid
                    elif kguid in FS_KGUID:
                        kparams['process_id'] = pid
                    if self.next_kevt_callback:
                        self.next_kevt_callback((kguid, opc,), cpuid,
                                                timestamp,
                                                kparams)
                except Exception as e:
                    print(traceback.print_exc())
                except KeyboardInterrupt:
                    pass
                finally:
                    Py_XDECREF(ktuple)
        else:
            free(info)

    cdef _decref(self, PyObject* o):
        pyo = None
        if o != NULL:
            pyo = <object>o
            Py_XDECREF(o)
        return pyo

    cdef _decref_params(self,  unordered_map[wstring, PyObject*] params):
        for kparam in params:
            Py_XDECREF(_wstring(kparam.first))
            if kparam.second != NULL:
                Py_XDECREF(kparam.second)

    cdef _underscore(self, o):
        return self.regex.sub(r'_\1', o).lower()

    cdef PyObject* __parse_property(self, USHORT in_type, USHORT out_type,
                                    BYTE* buf) nogil:
        """Parses the property value.

        Given the property input / output types,
        transforms the buffer with property payload.

        Parameters
        ----------

        {in|out}_type : USHORT
            The property input/output types. An input type can
            have multiple output types. For example, UINT16 input
            type can have HEXINT16 or PORT output types.

        buffer: BYTE
            The pointer to the property buffer.
        """
        if buf == NULL:
            return NULL

        if in_type == TDH_INTYPE_UNICODESTRING:
            return _unicode(<wchar_t*>buf)
        elif in_type == TDH_INTYPE_ANSISTRING:
            return _ansi(<char*>buf)
        elif in_type == TDH_INTYPE_UNICODECHAR:
            return _unicodec(buf)
        elif in_type == TDH_INTYPE_ANSICHAR:
            return _ansic(buf)

        elif in_type == TDH_INTYPE_INT8:
            return _i8(buf)
        elif in_type == TDH_INTYPE_UINT8:
            if out_type == TDH_OUTTYPE_HEXINT8:
                return _u8_hex(buf)
            else:
                return _u8(buf)

        elif in_type == TDH_INTYPE_INT16:
            return _i16(buf)
        elif in_type == TDH_INTYPE_UINT16:
            if out_type == TDH_OUTTYPE_HEXINT16:
                return _i16_hex(buf)
            elif out_type == TDH_OUTTYPE_PORT:
                return _ntohs(buf)
            else:
                return _u16(buf)

        elif in_type == TDH_INTYPE_INT32:
            return _i32(buf)
        elif in_type == TDH_INTYPE_UINT32:
            if out_type == TDH_OUTTYPE_HEXINT32:
                return _i32_hex(buf)
            elif out_type == TDH_OUTTYPE_IPV4:
                return ip_addr(buf)
            else:
                return _u32(buf)

        elif in_type == TDH_INTYPE_INT64:
            return _i64(buf)
        elif in_type == TDH_INTYPE_UINT64:
            if out_type == TDH_OUTTYPE_HEXINT64:
                return _i64_hex(buf)
            else:
                return _u64(buf)

        elif in_type == TDH_INTYPE_HEXINT32:
            return _i32_hex(buf)
        elif in_type ==  TDH_INTYPE_HEXINT64:
            return  _i64_hex(buf)

        elif in_type == TDH_INTYPE_FLOAT:
            return _float(buf)
        elif in_type == TDH_INTYPE_DOUBLE:
            return _double(buf)

        elif in_type == TDH_INTYPE_POINTER or \
                        in_type == TDH_INTYPE_SIZET:
            if self.pointer_size == 8:
                return _u64(buf)
            else:
                return _u32(buf)
        else:
            return NULL

    cdef BOOL __apply_filters(self, ULONG pid, ULONG tid,
                              PyObject* ktuple,
                              unordered_map[wstring, PyObject*] params,
                              BOOL defer) nogil:
        cdef BOOL drop = True

        # we don't want to capture any events
        # coming from the fibratus process
        # nor from the process we've declared
        # in the excluded process list
        if self.own_pid == pid:
            return True

        if self.__ktuple_equals(ktuple, ENUM_PROCESS) or \
            self.__ktuple_equals(ktuple, ENUM_THREAD) or \
            self.__ktuple_equals(ktuple, ENUM_IMAGE) or \
            self.__ktuple_equals(ktuple, REG_CREATE_KCB) or \
            self.__ktuple_equals(ktuple, REG_DELETE_KCB):
            return False

        # apply skip list as defined
        # in the configuration descriptor
        drop = self.__apply_skips(pid)
        if drop:
            return True
        elif self.image_filter != NULL:
            drop = True

        for i from 0 <= i < self.ktuple_filters.size():
            ktuple_filter = self.ktuple_filters.at(i)
            if self.__ktuple_equals(ktuple, ktuple_filter):
                drop = False
                break

        # apply pid filter
        if self.pid_filter != 0 and self.pid_filter != pid:
            drop = True
            # we got an invalid pid from the header
            # and we can't still drop the event
            if pid == INVALID_PID:
                drop = False
        elif self.image_filter != NULL:
            # apply image filter
            if defer:
                return False
            if pid == INVALID_PID:
                drop = False
            else:
                drop = self.__apply_image_filter(pid)
                # this only apply to `CreateProcess` events where
                # parent pid is mapped to an image which doesn't match
                # the child pid's image
                if drop and \
                        self.__ktuple_equals(ktuple, CREATE_PROCESS):
                    if params.size() > 0:
                        image_name = _wchar_t(params.at(IMAGE_FILE_NAME_PROP))
                        drop = wcscmp(_wcslwr(image_name),
                                      _wcslwr(self.image_filter)) != 0
        if drop:
            return True
        # now scan for the kernel event
        # properties to find the pid value
        drop = self.__apply_prop_filters(params)

        return drop

    cdef inline BOOL __apply_skips(self, ULONG pid) nogil:
        cdef BOOL ignored = False
        cdef unordered_map[ULONG, PROCESS_INFO].iterator proc_iterator = self.proc_map.find(pid)
        if proc_iterator != self.proc_map.end():
            for i from 0 <= i < self.skips.size():
                skip = self.skips.at(i)
                # compare the image name found
                # on the proc map with the value
                # as defined on the skip list
                pi = deref(proc_iterator).second
                if wcscmp(_wcslwr(pi.name), _wcslwr(skip)) == 0:
                    ignored = True
                    break
        return ignored

    cdef inline BOOL __apply_prop_filters(self, unordered_map[wstring, PyObject*] params) nogil:
        cdef unordered_map[wstring, PyObject*].iterator piter = params.begin()
        cdef BOOL drop = False
        cdef ULONG pid = 0

        while piter != params.end():
            prop = deref(piter)
            prop_name = prop.first

            # get the value of the pid property
            if prop_name.compare(PID_PROP) == 0:
                pid = PyLong_AsLong(prop.second)

            # apply the filters. At this point
            # we also check the kernel event is
            # not coming from the fibratus process
            if pid != 0:
                if pid == self.own_pid:
                    drop = True
                    break
                elif self.pid_filter != 0 and self.pid_filter != pid:
                    drop = True
                    break
                elif self.image_filter != NULL:
                    drop = self.__apply_image_filter(pid)
                    if drop:
                        break
            inc(piter)
        return drop

    cdef inline BOOL __apply_image_filter(self, ULONG pid) nogil:
        cdef BOOL drop = True
        proc_iterator = self.proc_map.find(pid)
        if proc_iterator != self.proc_map.end():
            pi = deref(proc_iterator).second
            drop = wcscmp(_wcslwr(pi.name),
                          _wcslwr(self.image_filter)) != 0
        return drop

    cdef PyObject* __wrap_ktuple(self, GUID guid, UCHAR opcode) nogil:
        cdef wchar_t buf[39]

        if string_from_guid(guid, buf, 39) > 0:
            kguid = PyUnicode_FromWideChar(_wcslwr(buf), 39)
            return build_ktuple(kguid, opcode)
        else:
            return NULL

    cdef inline BOOL __ktuple_equals(self, PyObject* k1, PyObject* k2) nogil:
        cdef BOOL ktuple_equals = False
        if PyLong_AsLong(PyTuple_GetItem(k1, 1)) == PyLong_AsLong(PyTuple_GetItem(k2, 1)):
            kguid1 = _wchar_t(PyTuple_GetItem(k1, 0))
            kguid2 = _wchar_t(PyTuple_GetItem(k2, 0))
            ktuple_equals = wcscmp(kguid1, kguid2) == 0
            if kguid1 != NULL:
                PyMem_Free(kguid1)
            if kguid2 != NULL:
                PyMem_Free(kguid2)
        return ktuple_equals
