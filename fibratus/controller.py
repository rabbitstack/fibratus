# Copyright 2015 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io
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

from ctypes import addressof, byref, cast, memmove, sizeof,  c_char, c_wchar
from ctypes import ArgumentError, pointer
import sys

from fibratus.apidefs.cdefs import ERROR_ALREADY_EXISTS, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, \
    ERROR_INVALID_PARAMETER, ERROR_SUCCESS
from fibratus.apidefs.etw import *
from fibratus.common import IO
from fibratus.errors import FibratusError


class KTraceProps():

    def __init__(self, buffer_size=1024):
        """Builds the tracing session properties.

        Parameters
        ---------

        buffer_size: int
            the amount of memory allocated for each trace buffer
        """

        # allocate buffer for the trace
        self.max_string_len = 1024
        self.buff_size = sizeof(EVENT_TRACE_PROPERTIES) + 2 * sizeof(c_wchar) * self.max_string_len

        self._buff = (c_char * self.buff_size)()
        self._props = cast(pointer(self._buff), POINTER(EVENT_TRACE_PROPERTIES))

        # set trace properties
        self._props.contents.wnode.buffer_size = self.buff_size
        self._props.contents.wnode.guid = KERNEL_TRACE_CONTROL_GUID
        self._props.contents.wnode.flags = WNODE_FLAG_TRACED_GUID
        self._props.contents.logger_name_offset = sizeof(EVENT_TRACE_PROPERTIES)
        self._props.contents.log_file_name_offset = 0
        self._props.contents.log_file_mode = PROCESS_TRACE_MODE_REAL_TIME
        self._props.contents.buffer_size = buffer_size

    def enable_kflags(self, syscall=False, cswitch=False):
        # enable the basic set of flags
        # for the kernel events
        self._props.contents.enable_flags = (EVENT_TRACE_FLAG_PROCESS |
            EVENT_TRACE_FLAG_REGISTRY |
            EVENT_TRACE_FLAG_THREAD |
            EVENT_TRACE_FLAG_DISK_IO |
            EVENT_TRACE_FLAG_DISK_FILE_IO |
            EVENT_TRACE_FLAG_FILE_IO |
            EVENT_TRACE_FLAG_FILE_IO_INIT |
            EVENT_TRACE_FLAG_IMAGE_LOAD |
            EVENT_TRACE_FLAG_NETWORK_TCPIP)

        # syscall / cswitch flags generate a LOT of kevents
        # and they are disabled by default
        if syscall:
            self._props.contents.enable_flags |= EVENT_TRACE_FLAG_SYSTEMCALL
        if cswitch:
            self._props.contents.enable_flags |= EVENT_TRACE_FLAG_CSWITCH

    def get(self):
        return self._props

    @property
    def logger_name(self):
        return c_wchar_p(addressof(self._props.contents) +
                         self._props.contents.logger_name_offset)

    @logger_name.setter
    def logger_name(self, logger_name):
        name_len = len(logger_name) + 1
        if self.max_string_len < name_len:
            raise ArgumentError("Logger name %s is too long" % logger_name)
        props = self._props
        logger = c_wchar_p(addressof(props.contents) + props.contents.logger_name_offset)
        memmove(logger,  c_wchar_p(logger_name), sizeof(c_wchar) * name_len)


class KTraceController():
    """Controls the life cycle of the kernel traces.

    """

    def __init__(self):
        self._handle = TRACEHANDLE()
        self._trace_name = None

    def __del__(self):
        if self._handle:
            self.stop_ktrace()

    def start_ktrace(self, name, kprops):
        """Starts a new trace.

        Parameters
        ---------

        name: str
            the name for the trace session
        kprops: KTraceProps
            an instance of the kernel trace properties
        """
        self._trace_name = name
        handle = TRACEHANDLE()
        kp = kprops.get()
        status = start_trace(byref(handle),
                             self._trace_name,
                             kp)
        self._handle = handle
        if status == ERROR_ALREADY_EXISTS:
            # the kernel logger trace session
            # is already running. Restart the trace.
            self.stop_ktrace()
            status = start_trace(byref(handle),
                                 self._trace_name,
                                 kp)
            if status != ERROR_SUCCESS:
                raise FibratusError('Unable to start fibratus')
            self._handle = handle
        elif status == ERROR_ACCESS_DENIED:
            # insufficient privileges
            IO.write_console("ERROR - You don't have administrative privileges. Stopping fibratus...")
            sys.exit()
        elif status == ERROR_BAD_LENGTH:
            raise FibratusError('Incorrect buffer size for the trace buffer')
        elif status == ERROR_INVALID_PARAMETER:
            raise FibratusError('Invalid trace handle or provider GUID')
        elif status != ERROR_SUCCESS:
            raise FibratusError('Unable to start fibratus')

    def stop_ktrace(self, kprops=None):
        """Stops the current running trace.

        Parameters
        ---------
        kprops: KTraceProps
            an instance of the kernel trace properties
        """
        kprops = kprops or KTraceProps()

        handle = self._handle
        self._handle = TRACEHANDLE()
        control_trace(handle,
                      self._trace_name,
                      kprops.get(),
                      EVENT_TRACE_CONTROL_STOP)
